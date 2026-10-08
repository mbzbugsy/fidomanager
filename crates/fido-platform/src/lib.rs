//! Platform integration contracts and the few OS-process primitives the worker needs.
//!
//! Everything `unsafe` that concerns *process* lifecycle (as opposed to libfido2) lives here so it
//! stays small, commented, and reviewable in one place. The only Security.framework binding is
//! `macos_code_signing` (ADR-017), compiled only with the `macos-code-signing` feature, which the
//! service enables and the worker never does.

pub mod build_identity;
#[cfg(unix)]
pub mod file_once;
#[cfg(all(target_os = "macos", feature = "macos-code-signing"))]
pub mod macos_code_signing;
pub mod os_version;
pub mod process;
#[cfg(unix)]
pub mod recovery_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPlacement {
    InProcessThread,
    ChildProcess,
    ElevatedBroker,
}
