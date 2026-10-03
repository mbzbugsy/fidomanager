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
        close_inherited_descriptors_except(None)
    }

    /// Only the fixed production authentication launch may retain descriptor 3.
    pub fn close_inherited_descriptors_except(keep: Option<c_int>) -> io::Result<usize> {
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
            if Some(fd) == keep {
                continue;
            }
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
pub use unix::{
    close_inherited_descriptors, close_inherited_descriptors_except, exit_immediately,
    parent_process_id,
};

#[cfg(unix)]
pub mod secret_channel {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{net::UnixStream, process::CommandExt};
    use std::process::Command;

    pub const SECRET_FD: i32 = 3;

    /// Both endpoints are CLOEXEC when pair() returns, before ordinary subsequent exec. On macOS
    /// socketpair creation and setting FD_CLOEXEC are separate operations, leaving a theoretical
    /// creation-to-fcntl window. Current FidoManager production spawning is controlled/serialized;
    /// future in-process helper/plugin spawn concurrency must revisit this assumption.
    /// Only this Command's post-fork child gets a dup at 3. No path/env/bootstrap secret.
    pub fn attach(command: &mut Command) -> io::Result<UnixStream> {
        let (parent, child) = UnixStream::pair()?;
        parent.set_write_timeout(Some(std::time::Duration::from_millis(100)))?;
        // SAFETY: pre_exec uses only async-signal-safe dup2/fcntl. Owning child in the closure keeps
        // the source descriptor alive through spawn; its CLOEXEC original closes on exec.
        unsafe {
            command.pre_exec(move || {
                let fd = child.as_raw_fd();
                if fd != SECRET_FD && libc::dup2(fd, SECRET_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(SECRET_FD, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(parent)
    }

    /// Must be called once in a child launched with the fixed authentication argument, before
    /// opening any other fd. Startup hygiene closes all unrelated inherited descriptors.
    pub fn receive() -> io::Result<UnixStream> {
        // SAFETY: test the fixed descriptor before adopting ownership, and forbid plain files.
        let mut kind: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&kind) as libc::socklen_t;
        let valid = unsafe {
            libc::getsockopt(
                SECRET_FD,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                std::ptr::from_mut(&mut kind).cast(),
                &mut len,
            )
        } == 0
            && kind == libc::SOCK_STREAM;
        if !valid {
            return Err(io::Error::other("secret channel unavailable"));
        }
        // SAFETY: unique adoption at worker start; no other owner exists in this process.
        let stream = unsafe { UnixStream::from_raw_fd(SECRET_FD) };
        stream.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
        // SAFETY: own fd; mark it CLOEXEC before any future child might exist.
        if unsafe { libc::fcntl(SECRET_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }
}

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
