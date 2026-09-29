//! Platform integration contracts.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPlacement {
    InProcessThread,
    ChildProcess,
    ElevatedBroker,
}
