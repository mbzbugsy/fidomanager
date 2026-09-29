//! Process-transparent service-to-worker messages.
//!
//! The protocol intentionally uses owned, serializable values only. The same contract can be
//! transported to an in-process worker thread or a future child/elevated worker without changing
//! service semantics.

use fido_core::{DeviceGeneration, ExecutionQuiescence, MutationOutcome};
use serde::{Deserialize, Serialize};

pub const WORKER_PROTOCOL_VERSION: u16 = 1;
/// Transport implementations must reject frames larger than this before deserialization.
pub const MAX_WORKER_FRAME_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerRequestId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CancellationId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerGeneration(pub u64);

/// Relative execution budget measured from service dispatch, never a wall-clock timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestBudgetMs(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerOperationClass {
    Control,
    ReadOnly,
    SensitiveRead,
    Mutation,
    Reset,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequestEnvelope {
    pub protocol_version: u16,
    pub request_id: WorkerRequestId,
    pub cancellation_id: CancellationId,
    pub operation_class: WorkerOperationClass,
    pub worker_generation: WorkerGeneration,
    pub device_generation: Option<DeviceGeneration>,
    pub budget_ms: RequestBudgetMs,
    pub request: WorkerRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequest {
    HealthCheck,
    Cancel {
        target_request_id: WorkerRequestId,
        target_cancellation_id: CancellationId,
    },
}

impl WorkerRequest {
    pub const fn operation_class(&self) -> WorkerOperationClass {
        WorkerOperationClass::Control
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponseEnvelope {
    pub protocol_version: u16,
    pub request_id: WorkerRequestId,
    pub worker_generation: WorkerGeneration,
    pub device_generation: Option<DeviceGeneration>,
    pub evidence: WorkerResponseEvidence,
    pub response: WorkerResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponseEvidence {
    pub execution_quiescence: ExecutionQuiescence,
    pub mutation_outcome: Option<MutationOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerResponse {
    Healthy,
    CancellationAccepted,
    Error { code: WorkerErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    ProtocolMismatch,
    DeadlineExpired,
    Cancelled,
    WorkerUnavailable,
    InternalFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_without_process_local_state() -> Result<(), Box<dyn std::error::Error>> {
        let request = WorkerRequest::HealthCheck;
        let envelope = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(7),
            cancellation_id: CancellationId(11),
            operation_class: request.operation_class(),
            worker_generation: WorkerGeneration(3),
            device_generation: None,
            budget_ms: RequestBudgetMs(2_000),
            request,
        };

        let encoded = serde_json::to_vec(&envelope)?;
        let decoded: WorkerRequestEnvelope = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, envelope);
        Ok(())
    }

    #[test]
    fn response_keeps_quiescence_separate_from_mutation_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = WorkerResponseEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(7),
            worker_generation: WorkerGeneration(3),
            device_generation: Some(DeviceGeneration(9)),
            evidence: WorkerResponseEvidence {
                execution_quiescence: ExecutionQuiescence::Active,
                mutation_outcome: Some(MutationOutcome::OutcomeUnknown),
            },
            response: WorkerResponse::Error {
                code: WorkerErrorCode::DeadlineExpired,
            },
        };

        let encoded = serde_json::to_vec(&response)?;
        let decoded: WorkerResponseEnvelope = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, response);
        Ok(())
    }

    #[test]
    fn request_envelope_rejects_unknown_fields() {
        let encoded = r#"{
            "protocol_version":1,
            "request_id":7,
            "cancellation_id":11,
            "operation_class":"control",
            "worker_generation":3,
            "device_generation":null,
            "budget_ms":2000,
            "request":{"kind":"health_check"},
            "unexpected":true
        }"#;

        assert!(serde_json::from_str::<WorkerRequestEnvelope>(encoded).is_err());
    }
}
