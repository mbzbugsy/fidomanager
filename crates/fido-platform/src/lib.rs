//! Platform integration contracts and the few OS-process primitives the worker needs.
//!
//! Everything `unsafe` that concerns *process* lifecycle (as opposed to libfido2) lives here so it
//! stays small, commented, and reviewable in one place.

pub mod process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPlacement {
    InProcessThread,
    ChildProcess,
    ElevatedBroker,
}
