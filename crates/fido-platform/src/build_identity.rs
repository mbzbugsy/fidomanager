//! Compile-time build identity shared by the application and the worker (ADR-017 §5.6, §5.8).
//!
//! The worker reports [`WORKER_BUILD_ID`] in `ChildHello`. In the `macos-release-signing` flavor it
//! is `<version>+<40-hex source commit>`, which the release-worker identity record must name; in
//! MAS uses `<version>+<40-hex source commit>.mas`; unsigned development remains
//! `<version>+development`. Conflicting production features cannot produce a shippable build.
//! Nothing here is read at runtime from the environment, arguments, files or the renderer.

/// Workspace release version (`Cargo.toml` `workspace.package.version`).
pub const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");

const COMMIT_LABEL: &str = env!("FIDOMANAGER_BUILD_COMMIT_LABEL");

/// The compiled-in release source commit. `Some` only in the release flavor and only when the
/// build supplied a well-formed commit.
pub const RELEASE_SOURCE_COMMIT: Option<&str> = if is_lower_hex(COMMIT_LABEL, 40) {
    Some(COMMIT_LABEL)
} else {
    None
};

/// Build identity the worker reports in `ChildHello` and the service expects from it.
#[cfg(not(feature = "macos-mas-signing"))]
pub const WORKER_BUILD_ID: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("FIDOMANAGER_BUILD_COMMIT_LABEL")
);
#[cfg(all(feature = "macos-mas-signing", not(feature = "macos-release-signing")))]
pub const WORKER_BUILD_ID: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("FIDOMANAGER_BUILD_COMMIT_LABEL"),
    ".mas"
);
#[cfg(all(feature = "macos-mas-signing", feature = "macos-release-signing"))]
pub const WORKER_BUILD_ID: &str =
    concat!(env!("CARGO_PKG_VERSION"), "+conflicting-signing-flavors");

/// Whether this build is the compile-time release-enforcement flavor.
pub const RELEASE_SIGNING_FLAVOR: bool = cfg!(any(
    feature = "macos-release-signing",
    feature = "macos-mas-signing"
));
pub const CONFLICTING_SIGNING_FLAVORS: bool = cfg!(all(
    feature = "macos-release-signing",
    feature = "macos-mas-signing"
));
pub const DEVELOPER_ID_SIGNING_FLAVOR: bool = cfg!(feature = "macos-release-signing");
pub const MAS_SIGNING_FLAVOR: bool = cfg!(feature = "macos-mas-signing");

// An optimized release-flavor build must carry its source commit. Debug builds of the flavor (for
// example `cargo clippy --all-features`) still compile, and their release enforcement fails closed
// at runtime because the commit is absent.
#[cfg(all(feature = "macos-release-signing", not(debug_assertions)))]
const _: () = assert!(
    RELEASE_SOURCE_COMMIT.is_some(),
    "the macos-release-signing flavor requires FIDOMANAGER_RELEASE_SOURCE_COMMIT at compile time"
);
#[cfg(all(feature = "macos-mas-signing", not(debug_assertions)))]
const _: () = assert!(
    RELEASE_SOURCE_COMMIT.is_some() && !CONFLICTING_SIGNING_FLAVORS,
    "MAS signing requires FIDOMANAGER_RELEASE_SOURCE_COMMIT and exactly one signing flavor"
);

/// `true` when `value` is exactly `len` lowercase hexadecimal characters.
pub const fn is_lower_hex(value: &str, len: usize) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != len {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let b = bytes[index];
        if !(b.is_ascii_digit() || (b >= b'a' && b <= b'f')) {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_is_version_plus_commit_label() {
        assert!(WORKER_BUILD_ID.starts_with(RELEASE_VERSION));
        let suffix = &WORKER_BUILD_ID[RELEASE_VERSION.len()..];
        if CONFLICTING_SIGNING_FLAVORS {
            assert_eq!(suffix, "+conflicting-signing-flavors");
            return;
        }
        let flavor = if cfg!(feature = "macos-mas-signing") {
            ".mas"
        } else {
            ""
        };
        match RELEASE_SOURCE_COMMIT {
            Some(commit) => assert_eq!(suffix, format!("+{commit}{flavor}")),
            None if RELEASE_SIGNING_FLAVOR => assert_eq!(suffix, format!("+unprovisioned{flavor}")),
            None => assert_eq!(suffix, "+development"),
        }
    }

    #[test]
    fn lower_hex_is_exact_length_and_lowercase_only() {
        assert!(is_lower_hex("0123456789abcdef", 16));
        assert!(!is_lower_hex("0123456789ABCDEF", 16));
        assert!(!is_lower_hex("0123456789abcde", 16));
        assert!(!is_lower_hex("0123456789abcdeg", 16));
        assert!(!is_lower_hex("", 1));
    }
}
