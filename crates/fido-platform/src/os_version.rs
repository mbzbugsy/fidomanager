//! macOS version and the dynamic code-validation network policy (ADR-017 §5.2).
//!
//! The version is read once, by the process itself, from the kernel
//! (`sysctlbyname("kern.osproductversion")`). It is never taken from the renderer, the
//! environment, arguments, a configuration file or `Info.plist`, and there is no lenient mode.
//!
//! The only thing the version selects is the network flag for *dynamic* validation:
//!
//! | macOS        | dynamic flags            |
//! | ------------ | ------------------------ |
//! | below 11.0   | rejected (fail closed)   |
//! | 11.0 – 11.2  | `kSecCSDefaultFlags`     |
//! | 11.3 and up  | `kSecCSNoNetworkAccess`  |
//!
//! The SDK header (`CSCommon.h`) states that `kSecCSNoNetworkAccess` "has always been usable for
//! SecStaticCode objects and is usable with SecCode objects starting with macOS 11.3". The code
//! requirement and every identity check are identical on both paths.

/// The reviewed deployment floor (`LSMinimumSystemVersion`).
pub const MINIMUM_SUPPORTED: MacOsVersion = MacOsVersion {
    major: 11,
    minor: 0,
    patch: 0,
};

/// First release whose dynamic validation accepts `kSecCSNoNetworkAccess`.
pub const DYNAMIC_NO_NETWORK_SINCE: MacOsVersion = MacOsVersion {
    major: 11,
    minor: 3,
    patch: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MacOsVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsVersionError {
    /// The version could not be read from the kernel.
    Unavailable,
    /// The version string is not `major.minor[.patch]` made of decimal digits.
    Malformed,
    /// Below the deployment floor, including the `10.16` compatibility value.
    BelowSupportedFloor,
}

impl std::fmt::Display for OsVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "the macOS version is unavailable",
            Self::Malformed => "the macOS version is malformed",
            Self::BelowSupportedFloor => "the macOS version is below the supported floor",
        })
    }
}

impl std::error::Error for OsVersionError {}

/// Network policy for dynamic (`SecCodeCheckValidity`) validation. Static validation always uses
/// `kSecCSNoNetworkAccess`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicNetworkPolicy {
    /// macOS 11.0 – 11.2: `kSecCSDefaultFlags`.
    DefaultFlags,
    /// macOS 11.3 and later: `kSecCSNoNetworkAccess`.
    NoNetworkAccess,
}

impl MacOsVersion {
    /// Strict parser: `major.minor` or `major.minor.patch`, ASCII digits only, no sign, no
    /// whitespace, no empty or extra components, each component at most 5 digits.
    pub fn parse(text: &str) -> Result<Self, OsVersionError> {
        let mut parts = text.split('.');
        let mut component = |required: bool| -> Result<Option<u32>, OsVersionError> {
            match parts.next() {
                None if !required => Ok(None),
                None => Err(OsVersionError::Malformed),
                Some(part) => {
                    if part.is_empty()
                        || part.len() > 5
                        || !part.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(OsVersionError::Malformed);
                    }
                    part.parse::<u32>()
                        .map(Some)
                        .map_err(|_| OsVersionError::Malformed)
                }
            }
        };
        let major = component(true)?.ok_or(OsVersionError::Malformed)?;
        let minor = component(true)?.ok_or(OsVersionError::Malformed)?;
        let patch = component(false)?.unwrap_or(0);
        if parts.next().is_some() {
            return Err(OsVersionError::Malformed);
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl DynamicNetworkPolicy {
    /// Selects the dynamic flag set for `version`, failing closed below the deployment floor.
    pub fn for_version(version: MacOsVersion) -> Result<Self, OsVersionError> {
        if version < MINIMUM_SUPPORTED {
            Err(OsVersionError::BelowSupportedFloor)
        } else if version < DYNAMIC_NO_NETWORK_SINCE {
            Ok(Self::DefaultFlags)
        } else {
            Ok(Self::NoNetworkAccess)
        }
    }

    /// Parses `text` and selects the policy; any parse failure is a rejection.
    pub fn for_version_text(text: &str) -> Result<Self, OsVersionError> {
        Self::for_version(MacOsVersion::parse(text)?)
    }
}

/// The running macOS version as reported by the kernel.
#[cfg(target_os = "macos")]
pub fn current() -> Result<MacOsVersion, OsVersionError> {
    let mut buffer = [0u8; 32];
    let mut length = buffer.len();
    // SAFETY: the name is a NUL-terminated literal, `buffer`/`length` describe a writable buffer
    // that outlives the call, and no new value is supplied (null, 0).
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || length == 0 || length > buffer.len() {
        return Err(OsVersionError::Unavailable);
    }
    // The kernel returns a NUL-terminated string; the terminator must be the last byte.
    let text = buffer[..length]
        .strip_suffix(&[0])
        .ok_or(OsVersionError::Malformed)?;
    let text = std::str::from_utf8(text).map_err(|_| OsVersionError::Malformed)?;
    MacOsVersion::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eleven_zero_through_eleven_two_use_default_flags() {
        for text in ["11.0", "11.0.1", "11.1", "11.2", "11.2.3"] {
            assert_eq!(
                DynamicNetworkPolicy::for_version_text(text),
                Ok(DynamicNetworkPolicy::DefaultFlags),
                "{text}"
            );
        }
    }

    #[test]
    fn eleven_three_and_later_use_no_network_access() {
        for text in [
            "11.3", "11.3.1", "11.7.10", "12.0", "13.6", "14.4.1", "15.0", "26.5.2",
        ] {
            assert_eq!(
                DynamicNetworkPolicy::for_version_text(text),
                Ok(DynamicNetworkPolicy::NoNetworkAccess),
                "{text}"
            );
        }
    }

    #[test]
    fn below_floor_and_compatibility_versions_fail_closed() {
        for text in ["10.16", "10.15.7", "10.0", "0.0"] {
            assert_eq!(
                DynamicNetworkPolicy::for_version_text(text),
                Err(OsVersionError::BelowSupportedFloor),
                "{text}"
            );
        }
    }

    #[test]
    fn malformed_versions_are_rejected() {
        for text in [
            "", "11", "11.", ".3", "11..3", "11.3.", "11.3.1.2", " 11.3", "11.3 ", "+11.3",
            "-11.3", "11.x", "11.3a", "١١.٣", "999999.0", "11,3", "11.3\0",
        ] {
            assert_eq!(
                DynamicNetworkPolicy::for_version_text(text),
                Err(OsVersionError::Malformed),
                "{text:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_running_kernel_reports_a_supported_version() -> Result<(), OsVersionError> {
        let version = current()?;
        assert!(version >= MINIMUM_SUPPORTED);
        DynamicNetworkPolicy::for_version(version)?;
        Ok(())
    }
}
