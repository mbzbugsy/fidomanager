//! Process-transparent service-to-worker messages.
//!
//! The protocol intentionally uses owned, serializable values only. The same contract can be
//! transported to an in-process worker thread or a future child/elevated worker without changing
//! service semantics.

use serde::{Deserialize, Serialize};

pub const WORKER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerRequestId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeadlineMs(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRequestEnvelope {
    pub protocol_version: u16,
    pub request_id: WorkerRequestId,
    pub deadline_ms: DeadlineMs,
    pub request: WorkerRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerRequest {
    HealthCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerResponseEnvelope {
    pub protocol_version: u16,
    pub request_id: WorkerRequestId,
    pub response: WorkerResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerResponse {
    Healthy,
    Error { code: WorkerErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    ProtocolMismatch,
    DeadlineExpired,
    WorkerUnavailable,
    InternalFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_without_process_local_state() {
        let request = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(7),
            deadline_ms: DeadlineMs(2_000),
            request: WorkerRequest::HealthCheck,
        };

        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: WorkerRequestEnvelope = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, request);
    }
}
