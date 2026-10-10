//! G5: pin an existing OS-resolved directory. No root creation, fallback or journal reads.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

pub struct AuthorityRoot(File);

impl AuthorityRoot {
    /// Only production caller passes the trusted FileManager result. All components must be
    /// existing directories; no canonicalize/follow/create/alternate-root behavior is allowed.
    pub fn open_resolved(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(io::Error::other("invalid authority root"));
        }
        if path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(io::Error::other("invalid authority root component"));
        }
        let directory = open_without_symlinks(path)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid takes no arguments.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(io::Error::other(
                "unsafe authority root ownership/permissions",
            ));
        }
        #[cfg(target_os = "macos")]
        reject_extended_acl(&directory)?;
        Ok(Self(directory))
    }

    pub fn directory(&self) -> &File {
        &self.0
    }
}

// Darwin checks the ENTIRE path atomically with O_NOFOLLOW_ANY. Opening ancestor directories
// for reading would require sandbox rights outside the container. No weaker flag fallback.
#[cfg(target_os = "macos")]
fn open_without_symlinks(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(target_os = "macos"))]
fn open_without_symlinks(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes()).map_err(io::Error::other)?;
        // SAFETY: pinned parent and live relative C string; fresh fd adopted once.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh owned descriptor from openat.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

// macOS mode bits alone do not describe ACL grants. A shared root with any extended ACL is
// outside the current exact policy; reject it rather than guessing which grants are harmless.
#[cfg(target_os = "macos")]
fn reject_extended_acl(directory: &File) -> io::Result<()> {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    // sys/acl.h: ACL_TYPE_EXTENDED=0x100, ACL_FIRST_ENTRY=0. Copy is owned by this caller.
    // SAFETY: live directory descriptor; no caller-owned buffer crosses this call.
    let acl = unsafe { acl_get_fd_np(directory.as_raw_fd(), 0x100) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // Darwin returns ENOENT for absence of an extended ACL on this live descriptor.
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: live OS-returned ACL, writable out-pointer; first-entry is the documented selector.
    let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = io::Error::last_os_error();
    // SAFETY: exactly one free of the owned ACL; no borrowed entry is used after this.
    unsafe { acl_free(acl) };
    // Darwin acl_get_entry returns 0 for an entry and -1/EINVAL for an empty ACL.
    if status == -1 && error.raw_os_error() == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(io::Error::other(
            "shared authority root ACL unavailable or nonempty",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn missing_relative_unsafe_or_symlink_roots_are_never_created_or_followed() {
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap_or_else(|_| panic!("synthetic fixture"))
            .join(format!(
                "g5-root-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| panic!("synthetic fixture"))
                    .as_nanos()
            ));
        fs::create_dir(&parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(AuthorityRoot::open_resolved(Path::new("relative")).is_err());
        assert!(AuthorityRoot::open_resolved(Path::new("/")).is_err());
        assert!(AuthorityRoot::open_resolved(&parent.join("missing")).is_err());
        assert!(!parent.join("missing").exists());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(AuthorityRoot::open_resolved(&parent).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let link = parent.with_extension("link");
        symlink(&parent, &link).unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(AuthorityRoot::open_resolved(&link).is_err());
        fs::create_dir(parent.join("nested"))
            .unwrap_or_else(|_| panic!("synthetic ancestor fixture"));
        fs::set_permissions(parent.join("nested"), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic nested mode"));
        assert!(AuthorityRoot::open_resolved(&parent.join("nested")).is_ok());
        assert!(AuthorityRoot::open_resolved(&link.join("nested")).is_err());
        assert!(AuthorityRoot::open_resolved(&parent.join("../escape")).is_err());
        let root =
            AuthorityRoot::open_resolved(&parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        // SAFETY: read flags of a live owned fd.
        assert_ne!(
            unsafe { libc::fcntl(root.directory().as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        fs::remove_file(link).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::remove_dir_all(parent).unwrap_or_else(|_| panic!("synthetic fixture"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn mode_private_root_with_acl_is_rejected() {
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap_or_else(|_| panic!("temporary root"))
            .join(format!("g5-acl-{}", std::process::id()));
        fs::create_dir(&path).unwrap_or_else(|_| panic!("synthetic directory"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("mode"));
        assert!(AuthorityRoot::open_resolved(&path).is_ok());
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap_or_else(|_| panic!("synthetic ACL"));
        assert!(status.success());
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|_| panic!("metadata"))
                .mode()
                & 0o777,
            0o700
        );
        assert!(AuthorityRoot::open_resolved(&path).is_err());
        fs::remove_dir(path).unwrap_or_else(|_| panic!("synthetic cleanup"));
    }

    #[test]
    fn pinned_directory_keeps_lock_and_storage_together_after_path_replacement() {
        use crate::instance_lock::{InstanceLock, InstanceLockError};
        use crate::recovery_file::DurableRecoveryFile;
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap_or_else(|_| panic!("synthetic fixture"))
            .join(format!(
                "g5-pin-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| panic!("synthetic fixture"))
                    .as_nanos()
            ));
        fs::create_dir(&parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let root =
            AuthorityRoot::open_resolved(&parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        let lock = InstanceLock::acquire_in_directory(root.directory())
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let moved = parent.with_extension("moved");
        fs::rename(&parent, &moved).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::create_dir(&parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let storage = DurableRecoveryFile::open_in_directory(root.directory())
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        storage
            .replace(b"synthetic pinned data")
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(!parent.join("fido-authority-recovery-v1").exists());
        assert_eq!(
            fs::read(moved.join("fido-authority-recovery-v1/incident.json"))
                .unwrap_or_else(|_| panic!("synthetic fixture")),
            b"synthetic pinned data"
        );
        assert!(matches!(
            InstanceLock::acquire_in_directory(root.directory()),
            Err(InstanceLockError::AlreadyHeld)
        ));
        drop(lock);
        fs::remove_dir_all(parent).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::remove_dir_all(moved).unwrap_or_else(|_| panic!("synthetic fixture"));
    }
}
