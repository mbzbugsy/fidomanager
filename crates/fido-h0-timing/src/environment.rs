//! Measurement context recorded once per session: OS, hardware model, filesystem of the scratch
//! journal and the pinned libfido2 revision. No user name, host name, path or device identifier.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub hardware_model: Option<String>,
    pub architecture: String,
    /// Filesystem type holding the scratch journal (macOS `f_fstypename`, e.g. "apfs").
    pub scratch_filesystem: Option<String>,
    pub libfido2_revision: String,
    pub tool_version: String,
}

/// libfido2 enables protocol logging in `fido_init()` when `FIDO_DEBUG` is present, whatever its
/// value. Its log includes device paths, so H0 refuses to start rather than leak them.
pub const LIBFIDO2_DEBUG_VARIABLE: &str = "FIDO_DEBUG";

pub fn debug_logging_requested(variable: Option<&std::ffi::OsStr>) -> bool {
    variable.is_some()
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &std::ffi::CStr) -> Option<String> {
    let mut size: libc::size_t = 0;
    // SAFETY: NUL-terminated name; a null buffer asks only for the required size.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
        || size > 256
    {
        return None;
    }
    let mut buffer = vec![0u8; size];
    // SAFETY: buffer has exactly `size` writable bytes; the kernel updates `size` to the length.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    buffer.truncate(size);
    let text = std::ffi::CStr::from_bytes_until_nul(&buffer).ok()?;
    Some(text.to_string_lossy().into_owned())
}

#[cfg(target_os = "macos")]
fn filesystem_type(path: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: zeroed statfs is a valid out-parameter; the path is NUL-terminated.
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stats) } != 0 {
        return None;
    }
    let name: Vec<u8> = stats
        .f_fstypename
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    Some(String::from_utf8_lossy(&name).into_owned())
}

#[cfg(target_os = "macos")]
pub fn collect(scratch: &std::path::Path) -> EnvironmentInfo {
    EnvironmentInfo {
        os: "macos".into(),
        os_version: sysctl_string(c"kern.osproductversion"),
        os_build: sysctl_string(c"kern.osversion"),
        hardware_model: sysctl_string(c"hw.model"),
        architecture: std::env::consts::ARCH.into(),
        scratch_filesystem: filesystem_type(scratch),
        libfido2_revision: crate::LIBFIDO2_REVISION.into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn collect(_scratch: &std::path::Path) -> EnvironmentInfo {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|text| text.trim().to_owned());
    EnvironmentInfo {
        os: std::env::consts::OS.into(),
        os_version: release,
        os_build: None,
        hardware_model: None,
        architecture: std::env::consts::ARCH.into(),
        scratch_filesystem: None,
        libfido2_revision: crate::LIBFIDO2_REVISION.into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_alone_requests_debug_logging() {
        assert!(debug_logging_requested(Some(std::ffi::OsStr::new(""))));
        assert!(debug_logging_requested(Some(std::ffi::OsStr::new("0"))));
        assert!(!debug_logging_requested(None));
    }

    #[test]
    fn environment_records_the_pinned_revision_and_no_identity() -> Result<(), serde_json::Error> {
        let info = collect(&std::env::temp_dir());
        assert_eq!(info.libfido2_revision.len(), 40);
        let text = serde_json::to_string(&info)?;
        for forbidden in ["hostname", "user", "home", "path"] {
            assert!(!text.to_lowercase().contains(forbidden), "{forbidden}");
        }
        Ok(())
    }
}
