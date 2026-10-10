//! Authority-owned Unix journal storage. macOS uses F_FULLFSYNC for record contents; the directory
//! is fsynced after atomic rename. No renderer path or same-user tamper-proof claim.
use std::ffi::CString;
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct DurableRecoveryFile {
    directory: File,
}
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
const RECORD: &std::ffi::CStr = c"incident.json";

fn validate(file: &File, directory: bool) -> io::Result<()> {
    let meta = file.metadata()?;
    // SAFETY: geteuid has no arguments and does not access caller memory.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid
        || meta.mode() & 0o077 != 0
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(io::Error::other(
            "unsafe recovery storage ownership/type/permissions",
        ));
    }
    Ok(())
}

fn sync_record(file: &File) -> io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: own live descriptor; F_FULLFSYNC takes no pointer argument. Failure (including
        // an unsupported filesystem) prevents durable acknowledgement rather than falling back.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn sync_directory(directory: &File) -> io::Result<()> {
    // SAFETY: own a live directory descriptor. Explicit fsync avoids relying on Rust's Apple
    // sync_all implementation (which uses F_FULLFSYNC even for directories). The final record
    // F_FULLFSYNC below flushes drive caches AFTER the renamed directory entry is synced.
    if unsafe { libc::fsync(directory.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Sync each newly created directory into its parent, including an app data root that did not
// exist yet. Merely syncing the final namespace would not persist a missing ancestor entry.
pub(crate) fn create_directory_durable(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => return Err(io::Error::other("recovery ancestor is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io::Error::other("recovery location must be absolute"))?;
    create_directory_durable(parent_path)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent_path)?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => sync_directory(&parent),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path)?.is_dir() {
                Ok(())
            } else {
                Err(io::Error::other("recovery directory replaced"))
            }
        }
        Err(error) => Err(error),
    }
}

impl DurableRecoveryFile {
    /// Caller supplies the framework-owned application data root. The private subdirectory is
    /// fixed, created 0700, checked without following symlinks, and pinned by an open descriptor.
    pub fn open(application_data: &Path) -> io::Result<Self> {
        if !application_data.is_absolute() {
            return Err(io::Error::other("recovery location must be absolute"));
        }
        create_directory_durable(application_data)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(application_data)?;
        let metadata = parent.metadata()?;
        // SAFETY: geteuid takes no pointer arguments.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "unsafe application data ownership/permissions",
            ));
        }
        let namespace = application_data.join("fido-authority-recovery-v1");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&namespace) {
            Ok(()) => sync_directory(&parent)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(namespace)?;
        validate(&directory, true)?;
        Ok(Self { directory })
    }

    fn open_at(&self, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
        // SAFETY: live directory descriptor and NUL-terminated relative constant/owned filename.
        // Mode is supplied for O_CREAT only; ownership transfers to File exactly once on success.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor owned by this call.
        let file = unsafe { File::from_raw_fd(fd) };
        validate(&file, false)?;
        Ok(file)
    }

    pub fn read_bounded(&self, maximum: usize) -> io::Result<Option<Vec<u8>>> {
        let file = match self.open_at(RECORD, libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(io::Error::other("recovery record exceeds bound"));
        }
        Ok(Some(bytes))
    }

    pub fn replace(&self, bytes: &[u8]) -> io::Result<()> {
        validate(&self.directory, true)?;
        // Never reuse or truncate a pre-existing temp file, including one left by a crash.
        let serial = NEXT_TEMP
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("temporary identity exhausted"))?;
        let temp = CString::new(format!("incident-{}-{serial}.tmp", std::process::id()))
            .map_err(io::Error::other)?;
        let mut file = self.open_at(&temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        let result = (|| {
            file.write_all(bytes)?;
            file.flush()?;
            sync_record(&file)?;
            // SAFETY: both relative names and the owned directory descriptor remain live. renameat
            // atomically replaces the directory entry without following a destination symlink.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temp.as_ptr(),
                    self.directory.as_raw_fd(),
                    RECORD.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            sync_directory(&self.directory)?;
            #[cfg(target_os = "macos")]
            sync_record(&file)?; // order the rename/ancestor metadata before the drive-cache flush
            Ok(())
        })();
        // SAFETY: anchored private temporary name. After rename ENOENT is harmless. This only
        // removes our own temp, never the incident record; failed sync keeps the published marker.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), temp.as_ptr(), 0);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fido-recovery-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        ))
    }
    #[test]
    fn durable_replacement_roundtrips_with_private_permissions() -> io::Result<()> {
        let root = root();
        let file = DurableRecoveryFile::open(&root)?;
        assert!(file.read_bounded(1024)?.is_none());
        file.replace(b"pending")?;
        file.replace(b"dispatch_capable")?;
        drop(file);
        let file = DurableRecoveryFile::open(&root)?;
        assert_eq!(file.read_bounded(1024)?, Some(b"dispatch_capable".to_vec()));
        assert!(file.read_bounded(2).is_err());
        assert_eq!(
            fs::metadata(root.join("fido-authority-recovery-v1/incident.json"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(file);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn rejects_symlinks_hardlinks_and_insecure_permissions() -> io::Result<()> {
        let root = root();
        let file = DurableRecoveryFile::open(&root)?;
        let record = root.join("fido-authority-recovery-v1/incident.json");
        let elsewhere = root.join("elsewhere");
        fs::write(&elsewhere, b"untouched")?;
        symlink(&elsewhere, &record)?;
        assert!(file.read_bounded(1024).is_err());
        file.replace(b"safe")?;
        assert_eq!(fs::read(&elsewhere)?, b"untouched");
        fs::hard_link(&record, root.join("link"))?;
        assert!(file.read_bounded(1024).is_err());
        fs::remove_file(root.join("link"))?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644))?;
        assert!(file.read_bounded(1024).is_err());
        fs::set_permissions(
            root.join("fido-authority-recovery-v1"),
            fs::Permissions::from_mode(0o755),
        )?;
        assert!(DurableRecoveryFile::open(&root).is_err());
        assert!(file.replace(b"blocked").is_err());
        drop(file);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn rejects_symlink_namespace() -> io::Result<()> {
        let root = root();
        fs::create_dir_all(root.join("other"))?;
        symlink(root.join("other"), root.join("fido-authority-recovery-v1"))?;
        assert!(DurableRecoveryFile::open(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
