//! Process-start handshake between the service and a freshly spawned worker.
//!
//! The worker is started with a fixed, empty argument list. Everything it needs to know arrives in
//! `ParentHello` over its stdin, and the service accepts the worker only after `ChildHello`
//! proves that both ends agree on protocol version, worker generation, and which process is
//! actually executing native code.

use serde::{Deserialize, Serialize};

use crate::{WORKER_PROTOCOL_VERSION, WorkerGeneration};

/// First frame, service to worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentHello {
    pub protocol_version: u16,
    pub worker_generation: WorkerGeneration,
    /// Process id of the service. The worker refuses to run unless this is still its parent, and
    /// keeps checking for the rest of its life (see the worker's parent-death watchdog).
    pub parent_pid: u32,
    /// Non-authorizing, application-lifetime scope for hashed connection display history.
    /// Never exposed to the renderer; absent disables history correlation.
    #[serde(default)]
    pub verification_display_scope: Option<[u8; 32]>,
}

/// Second frame, worker to service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildHello {
    pub protocol_version: u16,
    pub worker_generation: WorkerGeneration,
    /// Process id of the process that will execute native calls. The service compares it with the
    /// pid it spawned: if they differ (for example a wrapper script that forked the real worker),
    /// killing the spawned process would not stop native execution, so containment is unsound.
    pub worker_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    ProtocolMismatch,
    ZeroGeneration,
    GenerationMismatch,
    PidMismatch,
}

impl ParentHello {
    pub const fn new(worker_generation: WorkerGeneration, parent_pid: u32) -> Self {
        Self {
            protocol_version: WORKER_PROTOCOL_VERSION,
            worker_generation,
            parent_pid,
            verification_display_scope: None,
        }
    }

    /// Worker-side validation of the service's hello. `actual_parent_pid` is the worker's own
    /// observation of its parent, never a value taken from the frame.
    pub fn validate_for_worker(&self, actual_parent_pid: u32) -> Result<(), HandshakeError> {
        if self.protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(HandshakeError::ProtocolMismatch);
        }
        if self.worker_generation.0 == 0 {
            return Err(HandshakeError::ZeroGeneration);
        }
        if self.parent_pid != actual_parent_pid {
            return Err(HandshakeError::PidMismatch);
        }
        Ok(())
    }

    /// Service-side validation of the worker's reply. `spawned_pid` is the pid the service
    /// obtained from the OS when it spawned the child.
    pub fn validate_reply(
        &self,
        reply: &ChildHello,
        spawned_pid: u32,
    ) -> Result<(), HandshakeError> {
        if reply.protocol_version != self.protocol_version {
            return Err(HandshakeError::ProtocolMismatch);
        }
        if reply.worker_generation != self.worker_generation {
            return Err(HandshakeError::GenerationMismatch);
        }
        if reply.worker_pid != spawned_pid {
            return Err(HandshakeError::PidMismatch);
        }
        Ok(())
    }
}

impl ChildHello {
    pub const fn new(worker_generation: WorkerGeneration, worker_pid: u32) -> Self {
        Self {
            protocol_version: WORKER_PROTOCOL_VERSION,
            worker_generation,
            worker_pid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATION: WorkerGeneration = WorkerGeneration(4);

    #[test]
    fn matching_reply_is_accepted() {
        let parent = ParentHello::new(GENERATION, 100);
        let reply = ChildHello::new(GENERATION, 200);
        assert_eq!(parent.validate_reply(&reply, 200), Ok(()));
    }

    #[test]
    fn reply_with_other_protocol_generation_or_pid_is_rejected() {
        let parent = ParentHello::new(GENERATION, 100);

        let mut reply = ChildHello::new(GENERATION, 200);
        reply.protocol_version += 1;
        assert_eq!(
            parent.validate_reply(&reply, 200),
            Err(HandshakeError::ProtocolMismatch)
        );

        let reply = ChildHello::new(WorkerGeneration(5), 200);
        assert_eq!(
            parent.validate_reply(&reply, 200),
            Err(HandshakeError::GenerationMismatch)
        );

        let reply = ChildHello::new(GENERATION, 201);
        assert_eq!(
            parent.validate_reply(&reply, 200),
            Err(HandshakeError::PidMismatch)
        );
    }

    #[test]
    fn worker_rejects_wrong_parent_zero_generation_and_other_protocol() {
        assert_eq!(
            ParentHello::new(GENERATION, 100).validate_for_worker(100),
            Ok(())
        );
        assert_eq!(
            ParentHello::new(GENERATION, 100).validate_for_worker(1),
            Err(HandshakeError::PidMismatch)
        );
        assert_eq!(
            ParentHello::new(WorkerGeneration(0), 100).validate_for_worker(100),
            Err(HandshakeError::ZeroGeneration)
        );
        let mut hello = ParentHello::new(GENERATION, 100);
        hello.protocol_version = 0;
        assert_eq!(
            hello.validate_for_worker(100),
            Err(HandshakeError::ProtocolMismatch)
        );
    }

    #[test]
    fn hello_frames_reject_unknown_fields() {
        let encoded = r#"{"protocol_version":1,"worker_generation":1,"worker_pid":2,"x":1}"#;
        assert!(serde_json::from_str::<ChildHello>(encoded).is_err());
    }
}
