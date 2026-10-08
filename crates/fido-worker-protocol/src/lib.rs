//! Process-transparent service-to-worker messages.
//!
//! The protocol intentionally uses owned, serializable values only. The same contract is carried
//! unchanged across a process boundary today and can be carried behind an elevated broker later
//! without changing service semantics.

mod framing;
mod handshake;

pub use framing::{
    FRAME_HEADER_BYTES, FrameError, decode_message, encode_message, read_frame, read_message,
    write_frame, write_message,
};
pub use handshake::{ChildHello, HandshakeError, MAX_WORKER_BUILD_ID_BYTES, ParentHello};

pub use fido_core::inventory::InspectionError;

use fido_auth::{AcquisitionBinding, AuthenticationEvidence, GrantKind};
use fido_core::{Aaguid, DeviceGeneration, ExecutionQuiescence, MutationOutcome};
use serde::{Deserialize, Serialize};

/// Version 9 (M7.2a): `ChildHello` carries the worker `build_id` (ADR-017 §5.8).
pub const WORKER_PROTOCOL_VERSION: u16 = 9;
/// Largest frame the service accepts from a worker (responses). Transport implementations must
/// reject larger frames before deserialization, and before allocating their payload.
pub const MAX_WORKER_FRAME_BYTES: usize = 1_048_576;
/// Largest frame a worker accepts from the service. Requests are tiny and carry no payload data,
/// so the worker's inbound bound is much tighter than the response bound. It also stays below the
/// smallest OS pipe capacity so the service's single request write can never block on a pipe the
/// worker is draining.
pub const MAX_WORKER_REQUEST_FRAME_BYTES: usize = 16_384;
/// Largest `ParentHello`/`ChildHello` payload.
pub const MAX_WORKER_HANDSHAKE_FRAME_BYTES: usize = 1_024;
/// `WorkerRequestId` reserved for control exchanges the endpoint issues itself (for example the
/// post-handshake health check). The service's own request ids start at 1.
pub const ENDPOINT_CONTROL_REQUEST_ID: WorkerRequestId = WorkerRequestId(0);
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

/// Relative native-execution budget for one whole request, never a wall-clock timestamp.
///
/// The worker starts one deadline when it receives the request and hands each native sub-call only
/// the time that remains, so a request that makes several native calls cannot exceed this budget.
/// The endpoint adds its own small, named transport margin on top before it declares the exchange
/// dead and terminates the worker; that margin is transport time, not extra native time.
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
    InvalidCancellationTarget,
    InvalidCredentialId,
    InvalidIntentBinding,
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
            WorkerRequest::GetDeviceInfo { .. }
            | WorkerRequest::PrepareAuthentication { .. }
            | WorkerRequest::ValidateAuthentication { .. }
            | WorkerRequest::InspectCredentials { .. }
            | WorkerRequest::PreparePinMutation { .. }
            | WorkerRequest::ExecutePinMutation { .. }
            | WorkerRequest::PrepareCredentialDeletion { .. }
            | WorkerRequest::ProveCredentialDeletion { .. }
            | WorkerRequest::ExecuteCredentialDeletion { .. } => self.device_generation.is_some(),
            WorkerRequest::HealthCheck
            | WorkerRequest::Cancel { .. }
            | WorkerRequest::ListDevices => self.device_generation.is_none(),
        };
        if !generation_is_valid {
            return Err(WorkerRequestValidationError::InvalidDeviceGeneration);
        }

        if let WorkerRequest::Cancel {
            target_request_id,
            target_cancellation_id,
        } = &self.request
        {
            if target_request_id.0 == 0
                || target_cancellation_id.0 == 0
                || *target_request_id == self.request_id
                || *target_cancellation_id == self.cancellation_id
            {
                return Err(WorkerRequestValidationError::InvalidCancellationTarget);
            }
        }

        if let WorkerRequest::ProveCredentialDeletion { target, .. }
        | WorkerRequest::ExecuteCredentialDeletion { target, .. } = &self.request
            && !target.within_bounds()
        {
            return Err(WorkerRequestValidationError::InvalidCredentialId);
        }

        if matches!(
            &self.request,
            WorkerRequest::PrepareCredentialDeletion { binding, .. }
                | WorkerRequest::ProveCredentialDeletion { binding, .. }
                | WorkerRequest::ExecuteCredentialDeletion { binding, .. }
                if binding.intent_digest == [0; 32]
        ) {
            return Err(WorkerRequestValidationError::InvalidIntentBinding);
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequest {
    PrepareCredentialDeletion {
        device_id: WorkerDeviceId,
        binding: fido_auth::deletion::DeleteCredentialBinding,
    },
    /// Read-only current-session credential proof. Carries the PIN over the protected secret
    /// frame (never in this message) and runs BEFORE any durable dispatch record.
    ProveCredentialDeletion {
        binding: fido_auth::deletion::DeleteCredentialBinding,
        target: fido_core::inventory::DeletionIdentity,
    },
    /// Consumes the proven session for the one native delete. Carries no secret frame.
    ExecuteCredentialDeletion {
        binding: fido_auth::deletion::DeleteCredentialBinding,
        target: fido_core::inventory::DeletionIdentity,
    },
    PreparePinMutation {
        device_id: WorkerDeviceId,
        binding: fido_auth::mutation::PinMutationBinding,
    },
    ExecutePinMutation {
        binding: fido_auth::mutation::PinMutationBinding,
    },
    HealthCheck,
    Cancel {
        target_request_id: WorkerRequestId,
        target_cancellation_id: CancellationId,
    },
    ListDevices,
    GetDeviceInfo {
        device_id: WorkerDeviceId,
    },
    PrepareAuthentication {
        device_id: WorkerDeviceId,
        binding: AcquisitionBinding,
    },
    InspectCredentials {
        binding: AcquisitionBinding,
    },
    ValidateAuthentication {
        binding: AcquisitionBinding,
    },
}

// Future additions remain redacted by default, including all raw credential identity.
impl std::fmt::Debug for WorkerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkerRequest(<redacted>)")
    }
}

impl WorkerRequest {
    pub const fn operation_class(&self) -> WorkerOperationClass {
        match self {
            Self::PrepareCredentialDeletion { .. }
            | Self::ProveCredentialDeletion { .. }
            | Self::PreparePinMutation { .. } => WorkerOperationClass::SensitiveRead,
            Self::ExecuteCredentialDeletion { .. } | Self::ExecutePinMutation { .. } => {
                WorkerOperationClass::Mutation
            }
            Self::PrepareAuthentication { .. }
            | Self::ValidateAuthentication { .. }
            | Self::InspectCredentials { .. } => WorkerOperationClass::SensitiveRead,
            Self::HealthCheck | Self::Cancel { .. } => WorkerOperationClass::Control,
            Self::ListDevices | Self::GetDeviceInfo { .. } => WorkerOperationClass::ReadOnly,
        }
    }
}

/// Minimal discovery record returned before a device is opened for GetInfo.
///
/// Within one `WorkerGeneration`, the worker MUST strictly increase `device_generation` whenever a
/// `WorkerDeviceId` is rebound/reopened after observed absence or represents a different device
/// incarnation. The service deliberately treats regression or reuse-after-absence as a protocol
/// violation and quarantines that worker generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDiscoveredDevice {
    /// Display history only; never accepted in any authentication request/binding.
    #[serde(default)]
    pub verification_history_id: Option<[u8; 32]>,
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
    CredentialDeletionPrepared {
        binding: fido_auth::deletion::DeleteCredentialBinding,
        grant_kind: GrantKind,
        pin_retries: u8,
    },
    CredentialDeletionProved {
        binding: fido_auth::deletion::DeleteCredentialBinding,
        result: fido_auth::deletion::DeleteProofResult,
    },
    CredentialDeletionCompleted {
        binding: fido_auth::deletion::DeleteCredentialBinding,
        result: fido_auth::deletion::DeleteCredentialResult,
    },
    PinMutationPrepared {
        binding: fido_auth::mutation::PinMutationBinding,
        pin_retries: Option<u8>,
    },
    PinMutationCompleted {
        binding: fido_auth::mutation::PinMutationBinding,
        result: fido_auth::mutation::PinMutationResult,
    },
    AuthenticationPrepared {
        binding: AcquisitionBinding,
        grant_kind: GrantKind,
        pin_retries: Option<u8>,
    },
    CredentialsInspected {
        evidence: AuthenticationEvidence,
        inventory: Option<fido_core::inventory::OwnedInventory>,
        error: Option<InspectionError>,
    },
    AuthenticationValidated {
        evidence: AuthenticationEvidence,
    },
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
    fn deletion_target(credential_id: Vec<u8>) -> fido_core::inventory::DeletionIdentity {
        fido_core::inventory::DeletionIdentity {
            rp_hash: [1; 32],
            rp_text: "example.com".into(),
            credential_id,
            user_id: None,
        }
    }
    #[test]
    fn request_debug_never_discloses_identity() {
        let binding = fido_auth::deletion::DeleteCredentialBinding {
            session: fido_auth::AcquisitionBinding {
                worker_generation: 1,
                device_generation: fido_core::DeviceGeneration(1),
                workflow_id: fido_core::WorkflowId::from_raw(1),
                prompt_instance_id: fido_core::PromptInstanceId::from_raw(1),
                acquisition_id: fido_auth::AcquisitionId(1),
            },
            intent_digest: [9; 32],
        };
        for request in [
            WorkerRequest::ProveCredentialDeletion {
                binding,
                target: deletion_target(vec![17, 19, 23]),
            },
            WorkerRequest::ExecuteCredentialDeletion {
                binding,
                target: deletion_target(vec![17, 19, 23]),
            },
        ] {
            assert_eq!(format!("{request:?}"), "WorkerRequest(<redacted>)");
        }
    }

    use super::*;

    #[test]
    fn pin_protocol_is_typed_classified_secret_free_and_strict()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = fido_auth::mutation::PinMutationBinding {
            operation: fido_auth::mutation::PinOperation::ChangePin,
            session: AcquisitionBinding {
                worker_generation: 1,
                device_generation: DeviceGeneration(1),
                workflow_id: fido_core::WorkflowId::from_raw(1),
                prompt_instance_id: fido_core::PromptInstanceId::from_raw(1),
                acquisition_id: fido_auth::AcquisitionId(1),
            },
            intent_digest: [1; 32],
        };
        for request in [
            WorkerRequest::PreparePinMutation {
                device_id: WorkerDeviceId(1),
                binding,
            },
            WorkerRequest::ExecutePinMutation { binding },
        ] {
            let mutation = matches!(request, WorkerRequest::ExecutePinMutation { .. });
            let env = request_envelope(request, Some(DeviceGeneration(1)));
            assert_eq!(
                env.operation_class,
                if mutation {
                    WorkerOperationClass::Mutation
                } else {
                    WorkerOperationClass::SensitiveRead
                }
            );
            assert!(env.validate().is_ok());
            let value = serde_json::to_value(&env)?;
            assert_eq!(
                serde_json::from_value::<WorkerRequestEnvelope>(value.clone())?,
                env
            );
            for field in [
                "pin",
                "new_pin",
                "current_pin",
                "confirm_pin",
                "approval",
                "permit",
                "raw_ctap",
            ] {
                let mut v = value.clone();
                v["request"][field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<WorkerRequestEnvelope>(v).is_err());
                let mut v = value.clone();
                v["request"]["binding"][field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<WorkerRequestEnvelope>(v).is_err());
            }
            let mut bad = env.clone();
            bad.device_generation = None;
            assert!(bad.validate().is_err());
            bad = env.clone();
            bad.operation_class = WorkerOperationClass::Reset;
            assert!(bad.validate().is_err());
            bad = env;
            bad.protocol_version = 3;
            assert!(bad.validate().is_err());
        }
        Ok(())
    }
    #[test]
    fn credential_deletion_protocol_is_typed_bounded_and_strict()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = fido_auth::deletion::DeleteCredentialBinding {
            session: AcquisitionBinding {
                worker_generation: 3,
                device_generation: DeviceGeneration(1),
                workflow_id: fido_core::WorkflowId::from_raw(1),
                prompt_instance_id: fido_core::PromptInstanceId::from_raw(2),
                acquisition_id: fido_auth::AcquisitionId(3),
            },
            intent_digest: [9; 32],
        };
        for request in [
            WorkerRequest::PrepareCredentialDeletion {
                device_id: WorkerDeviceId(1),
                binding,
            },
            WorkerRequest::ProveCredentialDeletion {
                binding,
                target: deletion_target(vec![1, 2, 3]),
            },
            WorkerRequest::ExecuteCredentialDeletion {
                binding,
                target: deletion_target(vec![1, 2, 3]),
            },
        ] {
            let mutation = matches!(request, WorkerRequest::ExecuteCredentialDeletion { .. });
            let env = request_envelope(request, Some(DeviceGeneration(1)));
            assert_eq!(
                env.operation_class,
                if mutation {
                    WorkerOperationClass::Mutation
                } else {
                    WorkerOperationClass::SensitiveRead
                }
            );
            assert!(env.validate().is_ok());
            let value = serde_json::to_value(&env)?;
            assert_eq!(
                serde_json::from_value::<WorkerRequestEnvelope>(value.clone())?,
                env
            );
            for field in ["pin", "approval", "permit", "path", "raw_ctap"] {
                let mut hostile = value.clone();
                hostile["request"][field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<WorkerRequestEnvelope>(hostile).is_err());
                let mut hostile = value.clone();
                hostile["request"]["binding"][field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<WorkerRequestEnvelope>(hostile).is_err());
            }
            let mut no_generation = env.clone();
            no_generation.device_generation = None;
            assert_eq!(
                no_generation.validate(),
                Err(WorkerRequestValidationError::InvalidDeviceGeneration)
            );
            let mut wrong_class = env.clone();
            wrong_class.operation_class = WorkerOperationClass::Reset;
            assert_eq!(
                wrong_class.validate(),
                Err(WorkerRequestValidationError::OperationClassMismatch)
            );
        }

        let mut zero_digest = request_envelope(
            WorkerRequest::PrepareCredentialDeletion {
                device_id: WorkerDeviceId(1),
                binding,
            },
            Some(DeviceGeneration(1)),
        );
        if let WorkerRequest::PrepareCredentialDeletion { binding, .. } = &mut zero_digest.request {
            binding.intent_digest = [0; 32];
        }
        assert_eq!(
            zero_digest.validate(),
            Err(WorkerRequestValidationError::InvalidIntentBinding)
        );

        for credential_id in [
            Vec::new(),
            vec![1; fido_core::inventory::MAX_CREDENTIAL_ID_BYTES + 1],
        ] {
            for prove in [false, true] {
                let target = deletion_target(credential_id.clone());
                let request = if prove {
                    WorkerRequest::ProveCredentialDeletion { binding, target }
                } else {
                    WorkerRequest::ExecuteCredentialDeletion { binding, target }
                };
                let invalid = request_envelope(request, Some(DeviceGeneration(1)));
                assert_eq!(
                    invalid.validate(),
                    Err(WorkerRequestValidationError::InvalidCredentialId)
                );
            }
        }
        let mut zero_prove = request_envelope(
            WorkerRequest::ProveCredentialDeletion {
                binding,
                target: deletion_target(vec![1]),
            },
            Some(DeviceGeneration(1)),
        );
        if let WorkerRequest::ProveCredentialDeletion { binding, .. } = &mut zero_prove.request {
            binding.intent_digest = [0; 32];
        }
        assert_eq!(
            zero_prove.validate(),
            Err(WorkerRequestValidationError::InvalidIntentBinding)
        );
        Ok(())
    }

    #[test]
    fn generic_mutation_messages_are_not_protocol_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in ["set_pin", "change_pin", "reset", "delete_credential"] {
            let encoded = serde_json::json!({ "kind": kind });
            assert!(serde_json::from_value::<WorkerRequest>(encoded).is_err());
        }
        let binding = fido_auth::AcquisitionBinding {
            worker_generation: 1,
            device_generation: fido_core::DeviceGeneration(1),
            workflow_id: fido_core::WorkflowId::from_raw(1),
            prompt_instance_id: fido_core::PromptInstanceId::from_raw(1),
            acquisition_id: fido_auth::AcquisitionId(1),
        };
        for request in [
            WorkerRequest::HealthCheck,
            WorkerRequest::Cancel {
                target_request_id: WorkerRequestId(1),
                target_cancellation_id: CancellationId(1),
            },
            WorkerRequest::ListDevices,
            WorkerRequest::GetDeviceInfo {
                device_id: WorkerDeviceId(1),
            },
            WorkerRequest::PrepareAuthentication {
                device_id: WorkerDeviceId(1),
                binding,
            },
            WorkerRequest::InspectCredentials { binding },
            WorkerRequest::ValidateAuthentication { binding },
        ] {
            assert_ne!(request.operation_class(), WorkerOperationClass::Mutation);
        }
        Ok(())
    }

    #[test]
    fn authentication_round_trip_and_hostile_secret_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = AcquisitionBinding {
            worker_generation: 3,
            device_generation: DeviceGeneration(1),
            workflow_id: fido_core::WorkflowId::from_raw(u128::MAX - 1),
            prompt_instance_id: fido_core::PromptInstanceId::from_raw(u128::MAX),
            acquisition_id: fido_auth::AcquisitionId(7),
        };
        for request in [
            WorkerRequest::PrepareAuthentication {
                device_id: WorkerDeviceId(1),
                binding,
            },
            WorkerRequest::ValidateAuthentication { binding },
            WorkerRequest::InspectCredentials { binding },
        ] {
            let envelope = request_envelope(request, Some(DeviceGeneration(1)));
            assert_eq!(
                envelope.operation_class,
                WorkerOperationClass::SensitiveRead
            );
            assert!(envelope.validate().is_ok());
            let mut missing = envelope.clone();
            missing.device_generation = None;
            assert_eq!(
                missing.validate(),
                Err(WorkerRequestValidationError::InvalidDeviceGeneration)
            );
            let encoded = serde_json::to_string(&envelope)?;
            assert_eq!(
                serde_json::from_str::<WorkerRequestEnvelope>(&encoded)?,
                envelope
            );
            let mut value = serde_json::to_value(&envelope)?;
            for field in [
                "pin",
                "token",
                "approved",
                "path",
                "permissions",
                "deadline",
                "verification_history_id",
            ] {
                value["request"][field] = serde_json::json!("hostile-value");
                assert!(serde_json::from_value::<WorkerRequestEnvelope>(value.clone()).is_err());
                value["request"]
                    .as_object_mut()
                    .ok_or("object")?
                    .remove(field);
            }
        }
        Ok(())
    }

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
    fn cancel_cannot_target_itself_or_zero_identifiers() {
        let self_target = request_envelope(
            WorkerRequest::Cancel {
                target_request_id: WorkerRequestId(7),
                target_cancellation_id: CancellationId(11),
            },
            None,
        );
        assert_eq!(
            self_target.validate(),
            Err(WorkerRequestValidationError::InvalidCancellationTarget)
        );

        let zero_target = request_envelope(
            WorkerRequest::Cancel {
                target_request_id: WorkerRequestId(0),
                target_cancellation_id: CancellationId(9),
            },
            None,
        );
        assert_eq!(
            zero_target.validate(),
            Err(WorkerRequestValidationError::InvalidCancellationTarget)
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
    #[test]
    fn largest_application_inventory_fits_existing_frame() -> Result<(), Box<dyn std::error::Error>>
    {
        use fido_core::inventory::*;
        // Worst JSON expansion: each byte of a UTF-8 ASCII quote/backslash needs escaping,
        // IDs serialize as three-digit JSON numbers plus separators. Controls are rejected.
        let credential = OwnedCredential {
            id: vec![255; MAX_CREDENTIAL_ID_BYTES],
            user_id: Some(vec![255; MAX_USER_ID_BYTES]),
            user_name: Some("\\".repeat(MAX_USER_TEXT_BYTES)),
            display_name: Some("\\".repeat(MAX_USER_TEXT_BYTES)),
        };
        let mut rps: Vec<_> = (0..MAX_RPS)
            .map(|_| OwnedRp {
                hash: [255; 32],
                verified_text: Some("\\".repeat(MAX_RP_TEXT_BYTES)),
                issue: None,
                credentials: Vec::new(),
            })
            .collect();
        rps[0].credentials = vec![credential; MAX_CREDENTIALS];
        let inventory = OwnedInventory {
            metadata_existing: 128,
            rps,
        };
        assert!(inventory.within_bounds());
        let bytes = encode_message(&inventory)?;
        assert!(bytes.len() < MAX_WORKER_FRAME_BYTES / 2);
        Ok(())
    }
}
