//! M6.0 H0: non-destructive timing spike for the Option A durability path.
//!
//! Option A, from ADR-011, is: reconnect → candidate discovery → open/GetInfo validation →
//! durable `Pending` (already written before the unplug) → durable `DispatchCapable` → dispatch.
//! This crate measures every host-side component of that path up to the instant a would-be
//! dispatch frame reaches an executor, and then stops. It has no code path that can erase an
//! authenticator:
//!
//! - it depends on no production crate that can (only `fido-platform`, for the exact production
//!   journal durability mechanism);
//! - its native surface is a closed allowlist of libfido2 discovery/open/GetInfo functions and
//!   IOKit/CoreFoundation notification functions (no raw HID report I/O, no custom transport);
//! - the "executor" that receives the would-be frame is a thread with no device handle;
//! - `tests/no_destructive_capability.rs` enforces all of the above against the sources, the
//!   manifest, the binary's symbols and (on macOS) the linker's map of the final executable.
//!
//! There is no runtime "dry run" flag: there is nothing to switch on.

pub mod decision;
pub mod environment;
pub mod measurement;
pub mod operator;
pub mod report;
pub mod sample;
pub mod session;
pub mod stats;
pub mod would_dispatch;

#[cfg(unix)]
pub mod durability;

#[cfg(target_os = "macos")]
pub mod macos;

/// Pinned libfido2 revision this binary was built against (from `native/libfido2/source.lock.json`).
pub const LIBFIDO2_REVISION: &str = env!("FIDO_H0_LIBFIDO2_REVISION");

/// Version tag stored in every artefact so a later analysis can reject mismatched formats.
pub const FORMAT: &str = "fidomanager-h0-timing-v1";
