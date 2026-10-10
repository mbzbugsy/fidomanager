//! Single-instance authority lock (ADR-012) for builds whose application data lives in an App
//! Sandbox container (ADR-018).
//!
//! An exclusive, non-blocking `flock` on a private file inside the framework-derived application
//! data directory. Every instance of the same signed application resolves the same directory
//! (inside the sandbox it is the per-app container), so at most one process can hold the lock.
//! The kernel releases it when the holder exits for any reason, including a crash or `SIGKILL`,
//! so no stale state can block a later start. The descriptor is close-on-exec, so the worker never
//! inherits it and cannot keep the lock alive after the authority has gone.
//!
//! Like ADR-012's socket mechanism this is a coordination mechanism, not a security boundary
//! against other same-user processes.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const LOCK_FILE: &CStr = c"single-instance.lock";

/// Held for the lifetime of the authority process. Dropping it releases the lock.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

#[derive(Debug)]
pub enum InstanceLockError {
    /// Another live process of this application holds the lock.
    AlreadyHeld,
    /// The lock could not be established safely. Callers must fail closed.
    Unavailable(io::Error),
}

impl From<io::Error> for InstanceLockError {
    fn from(error: io::Error) -> Self {
        Self::Unavailable(error)
    }
}

impl InstanceLock {
    /// `application_data` is the framework-owned application data root (the same root the
    /// recovery journal uses). It is created `0700` if missing, opened without following
    /// symlinks, and must be owned by this user and not group/world-writable.
    pub fn acquire(application_data: &Path) -> Result<Self, InstanceLockError> {
        if !application_data.is_absolute() {
            return Err(io::Error::other("instance lock location must be absolute").into());
        }
        crate::recovery_file::create_directory_durable(application_data)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(application_data)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid takes no arguments and does not access caller memory.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other("unsafe application data ownership/permissions").into());
        }
        // SAFETY: live directory descriptor and a NUL-terminated relative constant name. The mode
        // applies to O_CREAT only; ownership of the new descriptor moves into `File` exactly once.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                LOCK_FILE.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a fresh descriptor owned by this call.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::other("unsafe instance lock ownership/type/permissions").into());
        }
        // SAFETY: own live descriptor; flock takes no pointer arguments.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                InstanceLockError::AlreadyHeld
            } else {
                InstanceLockError::Unavailable(error)
            });
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    // A process forked concurrently (other tests spawn children) shares every open file
    // description until its exec closes the CLOEXEC copies, so a release can be observed a moment
    // late. Retry briefly instead of asserting an instantaneous release.
    fn acquire_after_release(root: &Path) -> io::Result<InstanceLock> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match InstanceLock::acquire(root) {
                Ok(lock) => return Ok(lock),
                Err(InstanceLockError::AlreadyHeld) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => return Err(io::Error::other(format!("{error:?}"))),
            }
        }
    }

    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fido-instance-lock-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
    }

    #[test]
    fn second_holder_is_refused_until_the_first_releases() -> io::Result<()> {
        let root = root().join("nested/app-data");
        let first = InstanceLock::acquire(&root).map_err(|e| io::Error::other(format!("{e:?}")))?;
        assert!(matches!(
            InstanceLock::acquire(&root),
            Err(InstanceLockError::AlreadyHeld)
        ));
        drop(first);
        let again = acquire_after_release(&root)?;
        let lock = root.join("single-instance.lock");
        assert_eq!(fs::metadata(&lock)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&root)?.permissions().mode() & 0o777, 0o700);
        // SAFETY: reads the descriptor flags of a live descriptor owned by `again`.
        let flags = unsafe { libc::fcntl(again._file.as_raw_fd(), libc::F_GETFD) };
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "the worker must never inherit the lock"
        );
        drop(again);
        if let Some(top) = root.parent().and_then(Path::parent) {
            fs::remove_dir_all(top)?;
        }
        Ok(())
    }

    #[test]
    fn unsafe_locations_fail_closed() -> io::Result<()> {
        assert!(matches!(
            InstanceLock::acquire(Path::new("relative")),
            Err(InstanceLockError::Unavailable(_))
        ));

        let root = root();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770))?;
        assert!(matches!(
            InstanceLock::acquire(&root),
            Err(InstanceLockError::Unavailable(_))
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;

        let elsewhere = root.join("elsewhere");
        fs::write(&elsewhere, b"untouched")?;
        symlink(&elsewhere, root.join("single-instance.lock"))?;
        assert!(matches!(
            InstanceLock::acquire(&root),
            Err(InstanceLockError::Unavailable(_))
        ));
        assert_eq!(fs::read(&elsewhere)?, b"untouched");
        fs::remove_file(root.join("single-instance.lock"))?;

        fs::write(root.join("single-instance.lock"), b"")?;
        fs::set_permissions(
            root.join("single-instance.lock"),
            fs::Permissions::from_mode(0o644),
        )?;
        assert!(matches!(
            InstanceLock::acquire(&root),
            Err(InstanceLockError::Unavailable(_))
        ));

        let linked = root.join("linked-app-data");
        symlink(&root, &linked)?;
        assert!(matches!(
            InstanceLock::acquire(&linked),
            Err(InstanceLockError::Unavailable(_))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn a_separate_process_cannot_take_a_held_lock() -> io::Result<()> {
        let root = root();
        let held = InstanceLock::acquire(&root).map_err(|e| io::Error::other(format!("{e:?}")))?;
        // Another process's non-blocking flock on the same file: exit 0 means it was refused.
        let probe = "import fcntl, sys\nf = open(sys.argv[1], 'rb')\ntry:\n    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n    sys.exit(0)\nsys.exit(1)\n";
        let lock = root.join("single-instance.lock");
        let refused = std::process::Command::new("python3")
            .args(["-c", probe])
            .arg(&lock)
            .status()?;
        assert!(refused.success(), "another process acquired a held lock");
        drop(held);
        drop(acquire_after_release(&root)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
