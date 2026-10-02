//! The killable native FIDO worker.
//!
//! This crate is the only place libfido2 is linked. It runs as a child process of the service so
//! that a hung or crashing native call can be terminated, reaped, and replaced without taking the
//! trusted authority down with it (ADR-009).
//!
//! - [`engine`] validates requests and drives a native discovery backend.
//! - [`runtime`] is the process loop: handshake, request/response frames, parent-death watchdog.
//! - [`harden_process`] is the very first thing a worker `main` does.

pub mod engine;
pub mod runtime;

use fido_platform::process::close_inherited_descriptors;

/// Exit codes follow `sysexits.h` so a supervising human can tell failures apart. The service
/// never relies on them for correctness: any exit is simply "worker gone".
pub mod exit {
    /// Parent closed the request stream between frames: orderly shutdown.
    pub const ORDERLY: i32 = 0;
    /// Command line was not empty (the worker takes no arguments).
    pub const USAGE: i32 = 64;
    /// Malformed, oversized, truncated, or pipelined frame from the parent.
    pub const PROTOCOL: i32 = 65;
    /// The parent process is gone (stream broke or the watchdog saw a new parent).
    pub const PARENT_GONE: i32 = 69;
    /// Internal failure, including any panic.
    pub const INTERNAL: i32 = 70;
    /// Operating-system level setup failed (descriptor hygiene, thread creation).
    pub const OS: i32 = 71;
    /// Handshake with the parent failed or timed out.
    pub const HANDSHAKE: i32 = 76;
    /// The binary was built without a native backend.
    pub const CONFIG: i32 = 78;
}

/// Startup hygiene that must run before any thread or library owns a descriptor.
///
/// Closes every descriptor above stderr that the parent process leaked into this one (for example
/// from WebKit or IOKit code that did not set close-on-exec). Returns the exit code to terminate
/// with on failure.
pub fn harden_process() -> Result<(), i32> {
    close_inherited_descriptors()
        .map(|_| ())
        .map_err(|_| exit::OS)
}
