//! Process-transparent service-to-worker messages.
//!
//! The protocol intentionally uses owned, serializable values only. The same contract can be
//! transported to an in-process worker thread or a future child/elevated worker without changing
//! service semantics.

use fido_core::{Aaguid, DeviceGeneration, ExecutionQuiescence, MutationOutcome};
use serde::{Deserialize, Serialize};

pub const WORKER_PROTOCOL_VERSION: u16 = 1;
/// Transport implementations must reject frames larger than this before deserialization.
pub const MAX_WORKER_FRAME_BYTES: usize = 1_048_576;
pub const MAX_DISCOVERED_DEVICES: usize = 64;
pub const MAX_DEVICE_TEXT_BYTES: usize = 256;
pub const MAX_DEVICE_STRING_ITEMS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerRequestId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CancellationId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerGeneration(pub u64);

/// Worker-local identifier for a currently discovered authenticator.
///
/// This identifier is never exposed to the renderer and is meaningful only within one
/// `WorkerGeneration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerDeviceId(pub u64);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestValidationError {
    ProtocolMismatch,
    OperationClassMismatch,
    InvalidDeviceGeneration,
    ZeroExecutionBudget,
}

impl WorkerRequestEnvelope {
    pub fn validate(&self) -> Result<(), WorkerRequestValidationError> {
        if self.protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(WorkerRequestValidationError::ProtocolMismatch);
        }
        if self.operation_class != self.request.operation_class() {
            return Err(WorkerRequestValidationError::OperationClassMismatch);
        }
        if self.budget_ms.0 == 0 {
            return Err(WorkerRequestValidationError::ZeroExecutionBudget);
        }

        let generation_is_valid = match &self.request {
            WorkerRequest::GetDeviceInfo { .. } => self.device_generation.is_some(),
            WorkerRequest::HealthCheck
            | WorkerRequest::Cancel { .. }
            | WorkerRequest::ListDevices => self.device_generation.is_none(),
        };
        if !generation_is_valid {
            return Err(WorkerRequestValidationError::InvalidDeviceGeneration);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequest {
    HealthCheck,
    Cancel {
        target_request_id: WorkerRequestId,
        target_cancellation_id: CancellationId,
    },
    ListDevices,
    GetDeviceInfo {
        device_id: WorkerDeviceId,
    },
}

impl WorkerRequest {
    pub const fn operation_class(&self) -> WorkerOperationClass {
        match self {
            Self::HealthCheck | Self::Cancel { .. } => WorkerOperationClass::Control,
            Self::ListDevices | Self::GetDeviceInfo { .. } => WorkerOperationClass::ReadOnly,
        }
    }
}

/// Minimal discovery record returned before a device is opened for GetInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDiscoveredDevice {
    pub device_id: WorkerDeviceId,
    pub device_generation: DeviceGeneration,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDeviceOption {
    pub name: String,
    pub enabled: bool,
}

/// Bounded, validated GetInfo output. Raw native paths and native handles never cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDeviceInfo {
    pub device_id: WorkerDeviceId,
    pub aaguid: Option<Aaguid>,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub transports: Vec<String>,
    pub options: Vec<WorkerDeviceOption>,
    pub max_message_size: Option<u64>,
    pub firmware_version: Option<u64>,
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
    DevicesListed {
        devices: Vec<WorkerDiscoveredDevice>,
    },
    DeviceInfo {
        info: WorkerDeviceInfo,
    },
    Error {
        code: WorkerErrorCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    ProtocolMismatch,
    DeadlineExpired,
    Cancelled,
    WorkerUnavailable,
    DeviceAbsent,
    DeviceBusy,
    AccessDenied,
    UnsupportedDevice,
    MalformedDeviceData,
    InternalFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_envelope(
        request: WorkerRequest,
        device_generation: Option<DeviceGeneration>,
    ) -> WorkerRequestEnvelope {
        WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(7),
            cancellation_id: CancellationId(11),
            operation_class: request.operation_class(),
            worker_generation: WorkerGeneration(3),
            device_generation,
            budget_ms: RequestBudgetMs(2_000),
            request,
        }
    }

    #[test]
    fn request_round_trips_without_process_local_state() -> Result<(), Box<dyn std::error::Error>> {
        let envelope = request_envelope(WorkerRequest::ListDevices, None);

        let encoded = serde_json::to_vec(&envelope)?;
        let decoded: WorkerRequestEnvelope = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, envelope);
        assert_eq!(decoded.validate(), Ok(()));
        Ok(())
    }

    #[test]
    fn get_info_requires_device_generation() {
        let without_generation = request_envelope(
            WorkerRequest::GetDeviceInfo {
                device_id: WorkerDeviceId(4),
            },
            None,
        );
        assert_eq!(
            without_generation.validate(),
            Err(WorkerRequestValidationError::InvalidDeviceGeneration)
        );
    }

    #[test]
    fn operation_class_is_derived_from_request() {
        let mut envelope = request_envelope(WorkerRequest::ListDevices, None);
        envelope.operation_class = WorkerOperationClass::Mutation;
        assert_eq!(
            envelope.validate(),
            Err(WorkerRequestValidationError::OperationClassMismatch)
        );
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

    #[test]
    fn response_envelope_rejects_unknown_fields() {
        let encoded = r#"{
            "protocol_version":1,
            "request_id":7,
            "worker_generation":3,
            "device_generation":null,
            "evidence":{"execution_quiescence":"quiescent","mutation_outcome":null},
            "response":{"kind":"healthy"},
            "unexpected":true
        }"#;

        assert!(serde_json::from_str::<WorkerResponseEnvelope>(encoded).is_err());
    }
}
