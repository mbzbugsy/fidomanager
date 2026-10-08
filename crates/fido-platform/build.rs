//! Compile-time build identity (ADR-017 §5.6, §5.8).
//!
//! Only the `macos-release-signing` flavor compiles a release source commit in. The commit is read
//! from `FIDOMANAGER_RELEASE_SOURCE_COMMIT` at *compile time* only; nothing reads it at runtime.
//! A malformed value fails the build. A missing value in the release flavor yields the label
//! `unprovisioned`, which release enforcement rejects at runtime, and which an optimized build
//! refuses at compile time (see `src/build_identity.rs`).

use std::env;

const COMMIT_VARIABLE: &str = "FIDOMANAGER_RELEASE_SOURCE_COMMIT";

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn main() {
    println!("cargo:rerun-if-env-changed={COMMIT_VARIABLE}");
    let release_flavor = env::var_os("CARGO_FEATURE_MACOS_RELEASE_SIGNING").is_some();
    let label = if !release_flavor {
        "development".to_owned()
    } else {
        match env::var(COMMIT_VARIABLE) {
            Ok(commit) if is_commit(&commit) => commit,
            Ok(_) => panic!("{COMMIT_VARIABLE} must be exactly 40 lowercase hex characters"),
            Err(env::VarError::NotPresent) => "unprovisioned".to_owned(),
            Err(env::VarError::NotUnicode(_)) => panic!("{COMMIT_VARIABLE} is not valid UTF-8"),
        }
    };
    println!("cargo:rustc-env=FIDOMANAGER_BUILD_COMMIT_LABEL={label}");
}
