//! Worker engine: validates requests and runs them against a native discovery backend.
//!
//! The engine owns native device keys and device-generation tracking. It has no notion of where it
//! runs: the child-process runtime drives it today, and the same engine can sit behind an
//! elevated broker later. Native paths and libfido2 objects never leave this side of the boundary.

use fido_core::{Aaguid, DeviceGeneration, ExecutionQuiescence};
use fido_libfido2::{
    NativeDeadline, NativeDeviceInfo, NativeDeviceKey, NativeDiscoveredDevice,
    NativeDiscoveryBackend, NativeError, NativeErrorKind,
};
use fido_worker_protocol::{
    MAX_DISCOVERED_DEVICES, WORKER_PROTOCOL_VERSION, WorkerDeviceId, WorkerDeviceInfo,
    WorkerDeviceOption, WorkerErrorCode, WorkerGeneration, WorkerRequest, WorkerRequestEnvelope,
    WorkerResponse, WorkerResponseEnvelope, WorkerResponseEvidence,
};
use std::time::Duration;

#[derive(Debug, Clone)]
struct WorkerSlot {
    device_id: WorkerDeviceId,
    generation: DeviceGeneration,
    key: NativeDeviceKey,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    present: bool,
}

pub struct WorkerEngine<B> {
    backend: B,
    generation: WorkerGeneration,
    slots: Vec<WorkerSlot>,
    next_device_id: u64,
    secret: Option<Box<dyn std::io::Read + Send>>,
    authentication: Option<(
        fido_auth::AcquisitionBinding,
        Box<dyn fido_libfido2::NativeAuthenticationSession>,
    )>,
    auth_used: bool,
    mutation: Option<(
        fido_auth::mutation::PinMutationBinding,
        Box<dyn fido_libfido2::NativePinMutationSession>,
    )>,
    deletion: Option<(
        fido_auth::deletion::DeleteCredentialBinding,
        Box<dyn fido_libfido2::NativeCredentialDeletionSession>,
    )>,
    prepared_request_id: u64,
    verification_display_scope: Option<[u8; 32]>,
}

impl<B: NativeDiscoveryBackend> WorkerEngine<B> {
    pub fn new(backend: B, generation: WorkerGeneration) -> Self {
        Self {
            backend,
            generation,
            slots: Vec::new(),
            next_device_id: 1,
            secret: None,
            authentication: None,
            auth_used: false,
            mutation: None,
            deletion: None,
            prepared_request_id: 0,
            verification_display_scope: None,
        }
    }

    pub fn with_secret(mut self, secret: Option<Box<dyn std::io::Read + Send>>) -> Self {
        self.secret = secret;
        self
    }

    pub fn with_verification_display_scope(mut self, scope: Option<[u8; 32]>) -> Self {
        self.verification_display_scope = scope;
        self
    }

    fn prepare_authentication(
        &mut self,
        request: &WorkerRequestEnvelope,
        device_id: WorkerDeviceId,
        binding: fido_auth::AcquisitionBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        if self.auth_used
            || self.secret.is_none()
            || binding.worker_generation != self.generation.0
            || Some(binding.device_generation) != request.device_generation
            || binding.acquisition_id.0 == 0
            || binding.workflow_id.as_raw() == 0
            || binding.prompt_instance_id.as_raw() == 0
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        self.auth_used = true;
        self.prepared_request_id = request.request_id.0;
        let Some(slot) = self.slots.iter().find(|s| {
            s.device_id == device_id && s.present && s.generation == binding.device_generation
        }) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent,
            };
        };
        match self.backend.prepare_authentication(&slot.key, deadline) {
            Ok(session) => {
                let response = WorkerResponse::AuthenticationPrepared {
                    binding,
                    grant_kind: session.kind(),
                    pin_retries: session.pin_retries(),
                };
                self.authentication = Some((binding, session));
                response
            }
            Err(error) => {
                self.secret = None;
                WorkerResponse::Error {
                    code: map_native_error(&error, NativeOperation::GetInfo),
                }
            }
        }
    }

    fn validate_authentication(
        &mut self,
        request: &WorkerRequestEnvelope,
        binding: fido_auth::AcquisitionBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = self.authentication.take();
        let secret = self.secret.take();
        let (Some((expected, session)), Some(secret)) = (session, secret) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        if binding != expected || Some(binding.device_generation) != request.device_generation {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        match fido_auth::receive_secret(secret, binding, request.request_id.0) {
            Ok(pin) => WorkerResponse::AuthenticationValidated {
                evidence: session.validate(binding, pin, deadline),
            },
            Err(_) => WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            },
        }
    }

    fn inspect_credentials(
        &mut self,
        request: &WorkerRequestEnvelope,
        binding: fido_auth::AcquisitionBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = self.authentication.take();
        let secret = self.secret.take();
        let (Some((expected, session)), Some(secret)) = (session, secret) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        if binding != expected
            || Some(binding.device_generation) != request.device_generation
            || request.request_id.0 <= self.prepared_request_id
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        let Ok(pin) = fido_auth::receive_secret(secret, binding, request.request_id.0) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        let mut result = session.inspect(binding, pin, deadline);
        if !result.evidence.attached_puat_cleared {
            result.evidence.status = fido_auth::AuthenticationStatus::CleanupFailed;
            result.error = Some(fido_worker_protocol::InspectionError::CleanupFailed);
        }
        // Adapter cleanup cannot be overridden by a plausible-looking inventory.
        if !result.evidence.attached_puat_cleared
            || result.evidence.status != fido_auth::AuthenticationStatus::Validated
        {
            return WorkerResponse::CredentialsInspected {
                evidence: result.evidence,
                inventory: None,
                error: result.error,
            };
        }
        if result
            .inventory
            .as_ref()
            .is_some_and(|i| !i.within_bounds())
        {
            return WorkerResponse::CredentialsInspected {
                evidence: result.evidence,
                inventory: None,
                error: Some(fido_worker_protocol::InspectionError::Malformed),
            };
        }
        WorkerResponse::CredentialsInspected {
            evidence: result.evidence,
            inventory: result.inventory,
            error: result.error,
        }
    }

    fn prepare_credential_deletion(
        &mut self,
        request: &WorkerRequestEnvelope,
        device_id: WorkerDeviceId,
        binding: fido_auth::deletion::DeleteCredentialBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = binding.session;
        if self.auth_used
            || self.secret.is_none()
            || session.worker_generation != self.generation.0
            || Some(session.device_generation) != request.device_generation
            || session.acquisition_id.0 == 0
            || session.workflow_id.as_raw() == 0
            || session.prompt_instance_id.as_raw() == 0
            || binding.intent_digest == [0; 32]
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        self.auth_used = true;
        self.prepared_request_id = request.request_id.0;
        let Some(slot) = self.slots.iter().find(|slot| {
            slot.device_id == device_id
                && slot.present
                && slot.generation == session.device_generation
        }) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent,
            };
        };
        match self
            .backend
            .prepare_credential_deletion(&slot.key, deadline)
        {
            Ok(native)
                if matches!(
                    native.kind(),
                    fido_auth::GrantKind::CredMan | fido_auth::GrantKind::LegacyUnscoped
                ) && (1..=8).contains(&native.pin_retries()) =>
            {
                let grant_kind = native.kind();
                let pin_retries = native.pin_retries();
                self.deletion = Some((binding, native));
                WorkerResponse::CredentialDeletionPrepared {
                    binding,
                    grant_kind,
                    pin_retries,
                }
            }
            _ => {
                self.secret = None;
                WorkerResponse::Error {
                    code: WorkerErrorCode::UnsupportedDevice,
                }
            }
        }
    }

    fn execute_credential_deletion(
        &mut self,
        request: &WorkerRequestEnvelope,
        binding: fido_auth::deletion::DeleteCredentialBinding,
        target: fido_core::inventory::DeletionIdentity,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = self.deletion.take();
        let secret = self.secret.take();
        let (Some((expected, native)), Some(secret)) = (session, secret) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        if binding != expected
            || Some(binding.session.device_generation) != request.device_generation
            || request.request_id.0 <= self.prepared_request_id
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        let Ok(pin) = fido_auth::receive_secret(secret, binding.session, request.request_id.0)
        else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        WorkerResponse::CredentialDeletionCompleted {
            binding,
            result: native.execute(target, pin, deadline),
        }
    }

    fn prepare_pin_mutation(
        &mut self,
        request: &WorkerRequestEnvelope,
        device_id: WorkerDeviceId,
        binding: fido_auth::mutation::PinMutationBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = binding.session;
        if self.auth_used
            || self.secret.is_none()
            || session.worker_generation != self.generation.0
            || Some(session.device_generation) != request.device_generation
            || session.acquisition_id.0 == 0
            || session.workflow_id.as_raw() == 0
            || session.prompt_instance_id.as_raw() == 0
            || binding.intent_digest == [0; 32]
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        self.auth_used = true;
        self.prepared_request_id = request.request_id.0;
        let Some(slot) = self.slots.iter().find(|s| {
            s.device_id == device_id && s.present && s.generation == session.device_generation
        }) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent,
            };
        };
        match self
            .backend
            .prepare_pin_mutation(&slot.key, binding.operation, deadline)
        {
            Ok(native) if native.operation() == binding.operation => {
                let retries = native.pin_retries();
                self.mutation = Some((binding, native));
                WorkerResponse::PinMutationPrepared {
                    binding,
                    pin_retries: retries,
                }
            }
            _ => {
                self.secret = None;
                WorkerResponse::Error {
                    code: WorkerErrorCode::UnsupportedDevice,
                }
            }
        }
    }
    fn execute_pin_mutation(
        &mut self,
        request: &WorkerRequestEnvelope,
        binding: fido_auth::mutation::PinMutationBinding,
        deadline: NativeDeadline,
    ) -> WorkerResponse {
        let session = self.mutation.take();
        let secret = self.secret.take();
        let (Some((expected, native)), Some(secret)) = (session, secret) else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        if binding != expected
            || Some(binding.session.device_generation) != request.device_generation
            || request.request_id.0 <= self.prepared_request_id
        {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        }
        let Ok(secrets) =
            fido_auth::mutation::receive_mutation_secret(secret, binding, request.request_id.0)
        else {
            return WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch,
            };
        };
        WorkerResponse::PinMutationCompleted {
            binding,
            result: native.execute(secrets, deadline),
        }
    }

    /// Handles one request. The request's budget becomes **one** deadline, started here, that is
    /// shared by every native sub-call the request makes.
    pub fn handle(&mut self, request: WorkerRequestEnvelope) -> WorkerResponseEnvelope {
        if request.validate().is_err() || request.worker_generation != self.generation {
            self.mutation = None;
            self.deletion = None;
            self.authentication = None;
            self.secret = None;
            return self.response(
                &request,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch,
                },
            );
        }

        if self.authentication.is_some()
            && !matches!(
                request.request,
                WorkerRequest::ValidateAuthentication { .. }
                    | WorkerRequest::InspectCredentials { .. }
            )
        {
            self.mutation = None;
            self.deletion = None;
            self.authentication = None;
            self.secret = None;
            return self.response(
                &request,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch,
                },
            );
        }
        if self.mutation.is_some()
            && !matches!(request.request, WorkerRequest::ExecutePinMutation { .. })
        {
            self.mutation = None;
            self.deletion = None;
            self.secret = None;
            return self.response(
                &request,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch,
                },
            );
        }
        if self.deletion.is_some()
            && !matches!(
                request.request,
                WorkerRequest::ExecuteCredentialDeletion { .. }
            )
        {
            self.deletion = None;
            self.mutation = None;
            self.secret = None;
            return self.response(
                &request,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch,
                },
            );
        }
        let deadline = NativeDeadline::after(Duration::from_millis(request.budget_ms.0));
        let response = match &request.request {
            WorkerRequest::PrepareCredentialDeletion { device_id, binding } => {
                self.prepare_credential_deletion(&request, *device_id, *binding, deadline)
            }
            WorkerRequest::ExecuteCredentialDeletion { binding, target } => {
                self.execute_credential_deletion(&request, *binding, target.clone(), deadline)
            }
            WorkerRequest::PreparePinMutation { device_id, binding } => {
                self.prepare_pin_mutation(&request, *device_id, *binding, deadline)
            }
            WorkerRequest::ExecutePinMutation { binding } => {
                self.execute_pin_mutation(&request, *binding, deadline)
            }
            WorkerRequest::PrepareAuthentication { device_id, binding } => {
                self.prepare_authentication(&request, *device_id, *binding, deadline)
            }
            WorkerRequest::ValidateAuthentication { binding } => {
                self.validate_authentication(&request, *binding, deadline)
            }
            WorkerRequest::InspectCredentials { binding } => {
                self.inspect_credentials(&request, *binding, deadline)
            }
            WorkerRequest::HealthCheck => WorkerResponse::Healthy,
            // The process worker implements cancellation by termination: the service kills the
            // process at its deadline. A `Cancel` only reaches here while the worker is idle.
            WorkerRequest::Cancel { .. } => WorkerResponse::CancellationAccepted,
            WorkerRequest::ListDevices => match self.list_devices(deadline) {
                Ok(devices) => WorkerResponse::DevicesListed { devices },
                Err(code) => WorkerResponse::Error { code },
            },
            WorkerRequest::GetDeviceInfo { device_id } => {
                let Some(device_generation) = request.device_generation else {
                    return self.response(
                        &request,
                        WorkerResponse::Error {
                            code: WorkerErrorCode::ProtocolMismatch,
                        },
                    );
                };
                match self.get_device_info(*device_id, device_generation, deadline) {
                    Ok(info) => WorkerResponse::DeviceInfo { info },
                    Err(code) => WorkerResponse::Error { code },
                }
            }
        };

        self.response(&request, response)
    }

    fn response(
        &self,
        request: &WorkerRequestEnvelope,
        response: WorkerResponse,
    ) -> WorkerResponseEnvelope {
        WorkerResponseEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: request.request_id,
            worker_generation: self.generation,
            device_generation: request.device_generation,
            evidence: WorkerResponseEvidence {
                execution_quiescence: ExecutionQuiescence::Quiescent,
                mutation_outcome: match &response {
                    WorkerResponse::PinMutationCompleted { result, .. } => Some(result.outcome),
                    WorkerResponse::CredentialDeletionCompleted { result, .. } => {
                        Some(result.outcome)
                    }
                    _ => None,
                },
            },
            response,
        }
    }

    fn list_devices(
        &mut self,
        deadline: NativeDeadline,
    ) -> Result<Vec<fido_worker_protocol::WorkerDiscoveredDevice>, WorkerErrorCode> {
        let discovered = self
            .backend
            .manifest(deadline)
            .map_err(|error| map_native_error(&error, NativeOperation::Manifest))?;
        if discovered.len() > MAX_DISCOVERED_DEVICES {
            return Err(WorkerErrorCode::MalformedDeviceData);
        }
        if has_duplicate_native_keys(&discovered) {
            return Err(WorkerErrorCode::InternalFailure);
        }

        let next_slots = self.reconcile_manifest(discovered)?;
        let output = next_slots
            .iter()
            .filter(|slot| slot.present)
            .map(|slot| fido_worker_protocol::WorkerDiscoveredDevice {
                verification_history_id: self
                    .verification_display_scope
                    .as_ref()
                    .and_then(|scope| slot.key.verification_history_id(scope)),
                device_id: slot.device_id,
                device_generation: slot.generation,
                vendor_id: slot.vendor_id,
                product_id: slot.product_id,
                manufacturer: slot.manufacturer.clone(),
                product: slot.product.clone(),
            })
            .collect();
        self.slots = next_slots;
        Ok(output)
    }

    fn reconcile_manifest(
        &mut self,
        discovered: Vec<NativeDiscoveredDevice>,
    ) -> Result<Vec<WorkerSlot>, WorkerErrorCode> {
        let previous = self.slots.clone();
        let mut next = previous
            .iter()
            .cloned()
            .map(|mut slot| {
                slot.present = false;
                slot
            })
            .collect::<Vec<_>>();
        let mut next_device_id = self.next_device_id;

        for device in discovered {
            if let Some(index) = previous.iter().position(|slot| slot.key == device.key) {
                let prior = &previous[index];
                let slot = &mut next[index];
                let identity_changed =
                    prior.vendor_id != device.vendor_id || prior.product_id != device.product_id;
                if !prior.present || identity_changed {
                    slot.generation = DeviceGeneration(
                        slot.generation
                            .0
                            .checked_add(1)
                            .ok_or(WorkerErrorCode::InternalFailure)?,
                    );
                }
                slot.vendor_id = device.vendor_id;
                slot.product_id = device.product_id;
                slot.manufacturer = device.manufacturer;
                slot.product = device.product;
                slot.present = true;
            } else {
                let device_id = WorkerDeviceId(next_device_id);
                next_device_id = next_device_id
                    .checked_add(1)
                    .ok_or(WorkerErrorCode::InternalFailure)?;
                next.push(WorkerSlot {
                    device_id,
                    generation: DeviceGeneration(1),
                    key: device.key,
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    manufacturer: device.manufacturer,
                    product: device.product,
                    present: true,
                });
            }
        }

        self.next_device_id = next_device_id;
        Ok(next)
    }

    fn get_device_info(
        &mut self,
        device_id: WorkerDeviceId,
        device_generation: DeviceGeneration,
        deadline: NativeDeadline,
    ) -> Result<WorkerDeviceInfo, WorkerErrorCode> {
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.device_id == device_id)
        else {
            return Err(WorkerErrorCode::DeviceAbsent);
        };
        if !self.slots[index].present || self.slots[index].generation != device_generation {
            return Err(WorkerErrorCode::DeviceAbsent);
        }

        let key = self.slots[index].key.clone();
        match self.backend.get_info(&key, deadline) {
            Ok(info) => Ok(to_worker_device_info(device_id, info)),
            Err(error) => {
                if error.kind() == NativeErrorKind::Absent {
                    // Treat a mid-refresh disappearance as observed absence so a same-path replug
                    // must advance generation on the next manifest.
                    self.slots[index].present = false;
                }
                Err(map_native_error(&error, NativeOperation::GetInfo))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NativeOperation {
    Manifest,
    GetInfo,
}

fn map_native_error(error: &NativeError, operation: NativeOperation) -> WorkerErrorCode {
    match error.kind() {
        NativeErrorKind::Busy => WorkerErrorCode::DeviceBusy,
        NativeErrorKind::AccessDenied => WorkerErrorCode::AccessDenied,
        NativeErrorKind::TimedOut => WorkerErrorCode::DeadlineExpired,
        NativeErrorKind::Unsupported => WorkerErrorCode::UnsupportedDevice,
        NativeErrorKind::Absent => WorkerErrorCode::DeviceAbsent,
        NativeErrorKind::Malformed => WorkerErrorCode::MalformedDeviceData,
        NativeErrorKind::Unavailable => match operation {
            NativeOperation::Manifest => WorkerErrorCode::WorkerUnavailable,
            NativeOperation::GetInfo => WorkerErrorCode::DeviceAbsent,
        },
        NativeErrorKind::Internal => WorkerErrorCode::InternalFailure,
    }
}

fn has_duplicate_native_keys(devices: &[NativeDiscoveredDevice]) -> bool {
    devices.iter().enumerate().any(|(index, device)| {
        devices[index + 1..]
            .iter()
            .any(|candidate| candidate.key == device.key)
    })
}

fn to_worker_device_info(device_id: WorkerDeviceId, info: NativeDeviceInfo) -> WorkerDeviceInfo {
    WorkerDeviceInfo {
        device_id,
        aaguid: info.aaguid.map(Aaguid::from_bytes),
        versions: info.versions,
        extensions: info.extensions,
        transports: info.transports,
        options: info
            .options
            .into_iter()
            .map(|option| WorkerDeviceOption {
                name: option.name,
                enabled: option.enabled,
            })
            .collect(),
        max_message_size: info.max_message_size,
        firmware_version: info.firmware_version,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use fido_libfido2::NativeDeviceOption;
    use fido_worker_protocol::{CancellationId, RequestBudgetMs, WorkerRequestId};

    use super::*;

    struct ScriptedBackend {
        manifests: VecDeque<Result<Vec<NativeDiscoveredDevice>, NativeError>>,
        infos: VecDeque<Result<NativeDeviceInfo, NativeError>>,
    }

    impl NativeDiscoveryBackend for ScriptedBackend {
        fn manifest(
            &mut self,
            _deadline: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            self.manifests.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }

        fn get_info(
            &mut self,
            _key: &NativeDeviceKey,
            _deadline: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            self.infos.pop_front().unwrap_or_else(|| Ok(native_info()))
        }
    }

    fn key(value: u8) -> Result<NativeDeviceKey, NativeError> {
        NativeDeviceKey::from_bytes(vec![value])
    }

    fn native_device(value: u8) -> Result<NativeDiscoveredDevice, NativeError> {
        Ok(NativeDiscoveredDevice {
            key: key(value)?,
            vendor_id: 0x1234,
            product_id: 0x5678,
            manufacturer: Some("Example".to_owned()),
            product: Some("Authenticator".to_owned()),
        })
    }

    fn native_info() -> NativeDeviceInfo {
        NativeDeviceInfo {
            aaguid: Some([0x11; 16]),
            versions: vec!["FIDO_2_1".to_owned()],
            extensions: vec!["credProtect".to_owned()],
            transports: vec!["usb".to_owned()],
            options: vec![NativeDeviceOption {
                name: "rk".to_owned(),
                enabled: true,
            }],
            max_message_size: Some(1_200),
            firmware_version: Some(42),
        }
    }

    fn request(
        generation: WorkerGeneration,
        request_id: u64,
        request: WorkerRequest,
        device_generation: Option<DeviceGeneration>,
    ) -> WorkerRequestEnvelope {
        WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(request_id),
            cancellation_id: CancellationId(request_id + 100),
            operation_class: request.operation_class(),
            worker_generation: generation,
            device_generation,
            budget_ms: RequestBudgetMs(100),
            request,
        }
    }

    fn listed_device(
        response: WorkerResponseEnvelope,
    ) -> Option<fido_worker_protocol::WorkerDiscoveredDevice> {
        match response.response {
            WorkerResponse::DevicesListed { mut devices } if devices.len() == 1 => devices.pop(),
            _ => None,
        }
    }

    #[test]
    fn observed_absence_then_same_native_key_advances_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(7);
        let device = native_device(1)?;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![device.clone()]), Ok(Vec::new()), Ok(vec![device])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);

        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;
        assert!(
            listed_device(engine.handle(request(generation, 2, WorkerRequest::ListDevices, None,)))
                .is_none()
        );
        let replugged =
            listed_device(engine.handle(request(generation, 3, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("replugged device missing"))?;

        assert_eq!(first.device_id, replugged.device_id);
        assert_eq!(first.device_generation, DeviceGeneration(1));
        assert_eq!(replugged.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn get_info_absence_forces_generation_bump_on_next_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(3);
        let device = native_device(2)?;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![device.clone()]), Ok(vec![device])]),
            infos: VecDeque::from([Err(NativeError::new(NativeErrorKind::Absent, None))]),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;

        let info_response = engine.handle(request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: first.device_id,
            },
            Some(first.device_generation),
        ));
        assert!(matches!(
            info_response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent
            }
        ));

        let second =
            listed_device(engine.handle(request(generation, 3, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("second device missing"))?;
        assert_eq!(second.device_id, first.device_id);
        assert_eq!(second.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn changed_vid_pid_advances_generation_without_retargeting_same_incarnation()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(4);
        let first_device = native_device(3)?;
        let mut changed = first_device.clone();
        changed.product_id = 0x9999;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![first_device]), Ok(vec![changed])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;
        let second =
            listed_device(engine.handle(request(generation, 2, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("second device missing"))?;
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(second.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn stale_get_info_generation_is_rejected_before_native_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(5);
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![native_device(4)?])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let listed =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("device missing"))?;
        let response = engine.handle(request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: listed.device_id,
            },
            Some(DeviceGeneration(999)),
        ));
        assert!(matches!(
            response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent
            }
        ));
        Ok(())
    }

    #[test]
    fn responses_report_quiescence_only_after_the_native_call_returned()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(9);
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![native_device(5)?])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let response = engine.handle(request(generation, 1, WorkerRequest::ListDevices, None));
        assert!(matches!(
            response.response,
            WorkerResponse::DevicesListed { ref devices } if devices.len() == 1
        ));
        assert_eq!(
            response.evidence.execution_quiescence,
            ExecutionQuiescence::Quiescent
        );
        Ok(())
    }

    /// Records the deadline each native call receives.
    #[derive(Default)]
    struct DeadlineRecorder {
        manifest_remaining: Option<Duration>,
        info_remaining: Option<Duration>,
    }

    impl NativeDiscoveryBackend for DeadlineRecorder {
        fn manifest(
            &mut self,
            deadline: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            self.manifest_remaining = Some(deadline.remaining());
            Ok(vec![NativeDiscoveredDevice {
                key: NativeDeviceKey::from_bytes(vec![1])?,
                vendor_id: 1,
                product_id: 2,
                manufacturer: None,
                product: None,
            }])
        }

        fn get_info(
            &mut self,
            _key: &NativeDeviceKey,
            deadline: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            self.info_remaining = Some(deadline.remaining());
            Ok(native_info())
        }
    }

    #[test]
    fn request_budget_becomes_the_native_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(2);
        let mut engine = WorkerEngine::new(DeadlineRecorder::default(), generation);

        let mut list = request(generation, 1, WorkerRequest::ListDevices, None);
        list.budget_ms = RequestBudgetMs(5_000);
        let listed = listed_device(engine.handle(list))
            .ok_or_else(|| std::io::Error::other("device missing"))?;

        let mut info = request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: listed.device_id,
            },
            Some(listed.device_generation),
        );
        info.budget_ms = RequestBudgetMs(700);
        engine.handle(info);

        let manifest_remaining = engine
            .backend
            .manifest_remaining
            .ok_or_else(|| std::io::Error::other("manifest not called"))?;
        let info_remaining = engine
            .backend
            .info_remaining
            .ok_or_else(|| std::io::Error::other("get_info not called"))?;

        // The native call sees (almost) exactly the request budget: not a larger value, and not
        // a budget carried over from a previous request.
        assert!(manifest_remaining <= Duration::from_millis(5_000));
        assert!(manifest_remaining > Duration::from_millis(4_000));
        assert!(info_remaining <= Duration::from_millis(700));
        assert!(info_remaining > Duration::from_millis(200));
        Ok(())
    }

    #[test]
    fn worker_generation_mismatch_is_protocol_error() -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(10);
        let backend = ScriptedBackend {
            manifests: VecDeque::new(),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let response = engine.handle(request(
            WorkerGeneration(11),
            1,
            WorkerRequest::ListDevices,
            None,
        ));
        assert_eq!(response.worker_generation, generation);
        assert!(matches!(
            response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch
            }
        ));
        Ok(())
    }
    struct InspectionSession {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        cleanup: bool,
    }
    impl fido_libfido2::NativeAuthenticationSession for InspectionSession {
        fn kind(&self) -> fido_auth::GrantKind {
            fido_auth::GrantKind::CredMan
        }
        fn pin_retries(&self) -> Option<u8> {
            Some(8)
        }
        fn validate(
            self: Box<Self>,
            binding: fido_auth::AcquisitionBinding,
            pin: fido_auth::PinSecret,
            deadline: NativeDeadline,
        ) -> fido_auth::AuthenticationEvidence {
            self.inspect(binding, pin, deadline).evidence
        }
        fn inspect(
            self: Box<Self>,
            binding: fido_auth::AcquisitionBinding,
            pin: fido_auth::PinSecret,
            _: NativeDeadline,
        ) -> fido_libfido2::inspection::NativeInspection {
            drop(pin);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fido_libfido2::inspection::NativeInspection {
                evidence: fido_auth::AuthenticationEvidence {
                    binding,
                    kind: self.kind(),
                    status: fido_auth::AuthenticationStatus::Validated,
                    attached_puat_cleared: self.cleanup,
                },
                inventory: Some(fido_core::inventory::OwnedInventory {
                    metadata_existing: 0,
                    rps: Vec::new(),
                }),
                error: None,
            }
        }
    }
    struct InspectionBackend {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        cleanup: bool,
    }
    impl NativeDiscoveryBackend for InspectionBackend {
        fn manifest(
            &mut self,
            _: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            Ok(vec![native_device(1)?])
        }
        fn get_info(
            &mut self,
            _: &NativeDeviceKey,
            _: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            Ok(native_info())
        }
        fn prepare_authentication(
            &mut self,
            _: &NativeDeviceKey,
            _: NativeDeadline,
        ) -> Result<Box<dyn fido_libfido2::NativeAuthenticationSession>, NativeError> {
            Ok(Box::new(InspectionSession {
                calls: self.calls.clone(),
                cleanup: self.cleanup,
            }))
        }
    }
    #[test]
    fn inspection_one_shot_order_binding_secret_and_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        use fido_auth::{AcquisitionBinding, AcquisitionId, PinSecret};
        use fido_core::{PromptInstanceId, WorkflowId};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let generation = WorkerGeneration(1);
        let binding = AcquisitionBinding {
            worker_generation: 1,
            device_generation: DeviceGeneration(1),
            workflow_id: WorkflowId::from_raw(1),
            prompt_instance_id: PromptInstanceId::from_raw(1),
            acquisition_id: AcquisitionId(1),
        };
        for scenario in 0..7 {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut bytes = Vec::new();
            let pin = PinSecret::collect(|b| {
                b[..4].copy_from_slice(b"fake");
                Some(4)
            })
            .map_err(|_| "pin")?;
            fido_auth::send_secret(&mut bytes, binding, 3, pin).map_err(|_| "secret transport")?;
            let mut engine = WorkerEngine::new(
                InspectionBackend {
                    calls: calls.clone(),
                    cleanup: scenario != 6,
                },
                generation,
            )
            .with_secret(Some(Box::new(std::io::Cursor::new(bytes))));
            engine.handle(request(generation, 1, WorkerRequest::ListDevices, None));
            if scenario != 1 {
                let response = engine.handle(request(
                    generation,
                    2,
                    WorkerRequest::PrepareAuthentication {
                        device_id: WorkerDeviceId(1),
                        binding,
                    },
                    Some(DeviceGeneration(1)),
                ));
                assert!(matches!(
                    response.response,
                    WorkerResponse::AuthenticationPrepared { .. }
                ));
            }
            if scenario == 2 {
                engine.handle(request(generation, 9, WorkerRequest::HealthCheck, None));
            }
            let mut submitted = binding;
            if scenario == 3 {
                submitted.acquisition_id = AcquisitionId(2);
            }
            let id = if scenario == 4 {
                2
            } else if scenario == 5 {
                4
            } else {
                3
            };
            let response = engine.handle(request(
                generation,
                id,
                WorkerRequest::InspectCredentials { binding: submitted },
                Some(DeviceGeneration(1)),
            ));
            assert_eq!(response.evidence.mutation_outcome, None);
            if scenario == 0 {
                assert!(matches!(
                    response.response,
                    WorkerResponse::CredentialsInspected {
                        inventory: Some(_),
                        ..
                    }
                ));
            } else if scenario == 6 {
                assert!(matches!(
                    response.response,
                    WorkerResponse::CredentialsInspected {
                        inventory: None,
                        evidence: fido_auth::AuthenticationEvidence {
                            status: fido_auth::AuthenticationStatus::CleanupFailed,
                            ..
                        },
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    response.response,
                    WorkerResponse::Error {
                        code: WorkerErrorCode::ProtocolMismatch
                    }
                ));
            }
            assert!(engine.authentication.is_none() && engine.secret.is_none());
            let second = engine.handle(request(
                generation,
                8,
                WorkerRequest::InspectCredentials { binding },
                Some(DeviceGeneration(1)),
            ));
            assert!(matches!(
                second.response,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch
                }
            ));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(scenario == 0 || scenario == 6)
            );
        }
        Ok(())
    }
    fn deletion_target(credential_id: Vec<u8>) -> fido_core::inventory::DeletionIdentity {
        fido_core::inventory::DeletionIdentity {
            rp_hash: [1; 32],
            rp_text: "example.com".into(),
            credential_id,
            user_id: None,
        }
    }
    struct DeletionBackend {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        compatible: bool,
    }
    struct DeletionSession {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        compatible: bool,
    }
    impl fido_libfido2::NativeCredentialDeletionSession for DeletionSession {
        fn kind(&self) -> fido_auth::GrantKind {
            if self.compatible {
                fido_auth::GrantKind::CredMan
            } else {
                fido_auth::GrantKind::CredManReadOnly
            }
        }
        fn pin_retries(&self) -> u8 {
            8
        }
        fn execute(
            self: Box<Self>,
            target: fido_core::inventory::DeletionIdentity,
            pin: fido_auth::PinSecret,
            _: NativeDeadline,
        ) -> fido_auth::deletion::DeleteCredentialResult {
            assert_eq!(target.credential_id, vec![1, 2, 3]);
            drop(pin);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fido_auth::deletion::DeleteCredentialResult::from_code(true, 0, true)
        }
    }
    impl NativeDiscoveryBackend for DeletionBackend {
        fn manifest(
            &mut self,
            _: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            Ok(vec![native_device(1)?])
        }
        fn get_info(
            &mut self,
            _: &NativeDeviceKey,
            _: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            Ok(native_info())
        }
        fn prepare_credential_deletion(
            &mut self,
            _: &NativeDeviceKey,
            _: NativeDeadline,
        ) -> Result<Box<dyn fido_libfido2::NativeCredentialDeletionSession>, NativeError> {
            Ok(Box::new(DeletionSession {
                calls: self.calls.clone(),
                compatible: self.compatible,
            }))
        }
    }

    #[test]
    fn deletion_requires_exact_one_use_preparation_binding_secret_and_id()
    -> Result<(), Box<dyn std::error::Error>> {
        use fido_auth::{AcquisitionBinding, AcquisitionId, PinSecret};
        use fido_core::{PromptInstanceId, WorkflowId};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let binding = fido_auth::deletion::DeleteCredentialBinding {
            session: AcquisitionBinding {
                worker_generation: 1,
                device_generation: DeviceGeneration(1),
                workflow_id: WorkflowId::from_raw(1),
                prompt_instance_id: PromptInstanceId::from_raw(1),
                acquisition_id: AcquisitionId(1),
            },
            intent_digest: [9; 32],
        };

        for scenario in 0..20 {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut secret = Vec::new();
            let pin = PinSecret::collect(|bytes| {
                bytes[..4].copy_from_slice(b"fake");
                Some(4)
            })
            .map_err(|_| "pin")?;
            fido_auth::send_secret(&mut secret, binding.session, 3, pin).map_err(|_| "secret")?;
            if scenario == 8 {
                secret.pop();
            }
            if scenario == 9 {
                secret.push(1);
            }
            if scenario == 16 {
                secret[0] ^= 0xff;
            }

            let mut engine = WorkerEngine::new(
                DeletionBackend {
                    calls: calls.clone(),
                    compatible: scenario != 10,
                },
                WorkerGeneration(1),
            )
            .with_secret(Some(Box::new(std::io::Cursor::new(secret))));
            engine.handle(request(
                WorkerGeneration(1),
                1,
                WorkerRequest::ListDevices,
                None,
            ));

            if scenario != 1 {
                let mut prepared_binding = binding;
                if scenario == 13 {
                    prepared_binding.session.device_generation = DeviceGeneration(2);
                }
                if scenario == 14 {
                    prepared_binding.session.worker_generation = 2;
                }
                if scenario == 19 {
                    prepared_binding.session.acquisition_id = AcquisitionId(0);
                }
                let prepared = engine.handle(request(
                    WorkerGeneration(1),
                    2,
                    WorkerRequest::PrepareCredentialDeletion {
                        device_id: WorkerDeviceId(if scenario == 12 { 99 } else { 1 }),
                        binding: prepared_binding,
                    },
                    Some(DeviceGeneration(1)),
                ));
                if matches!(scenario, 10 | 12 | 13 | 14 | 19) {
                    assert!(matches!(prepared.response, WorkerResponse::Error { .. }));
                } else {
                    assert!(matches!(
                        prepared.response,
                        WorkerResponse::CredentialDeletionPrepared {
                            grant_kind: fido_auth::GrantKind::CredMan,
                            pin_retries: 8,
                            ..
                        }
                    ));
                }
            }

            if scenario == 11 || scenario == 15 {
                let interrupt = engine.handle(request(
                    WorkerGeneration(1),
                    3,
                    if scenario == 11 {
                        WorkerRequest::PrepareCredentialDeletion {
                            device_id: WorkerDeviceId(1),
                            binding,
                        }
                    } else {
                        WorkerRequest::GetDeviceInfo {
                            device_id: WorkerDeviceId(1),
                        }
                    },
                    Some(DeviceGeneration(1)),
                ));
                assert!(matches!(interrupt.response, WorkerResponse::Error { .. }));
                assert!(engine.deletion.is_none() && engine.secret.is_none());
            }
            let mut submitted = binding;
            let mut worker = WorkerGeneration(1);
            let request_id = if scenario == 17 { 2 } else { 3 };
            let mut credential_id = vec![1, 2, 3];
            match scenario {
                2 => submitted.intent_digest = [8; 32],
                3 => submitted.session.device_generation = DeviceGeneration(2),
                4 => submitted.session.workflow_id = WorkflowId::from_raw(2),
                5 => submitted.session.prompt_instance_id = PromptInstanceId::from_raw(2),
                6 => submitted.session.acquisition_id = AcquisitionId(2),
                7 => worker = WorkerGeneration(2),
                _ => {}
            }
            if scenario == 18 {
                credential_id.clear();
            }
            let response = engine.handle(request(
                worker,
                request_id,
                WorkerRequest::ExecuteCredentialDeletion {
                    binding: submitted,
                    target: deletion_target(credential_id),
                },
                Some(submitted.session.device_generation),
            ));

            if scenario == 0 {
                assert!(matches!(
                    response.response,
                    WorkerResponse::CredentialDeletionCompleted { .. }
                ));
                assert_eq!(
                    response.evidence.mutation_outcome,
                    Some(fido_core::MutationOutcome::ConfirmedSuccessful)
                );
            } else {
                assert!(matches!(response.response, WorkerResponse::Error { .. }));
            }
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(scenario == 0));

            let replay = engine.handle(request(
                WorkerGeneration(1),
                8,
                WorkerRequest::ExecuteCredentialDeletion {
                    binding,
                    target: deletion_target(vec![1, 2, 3]),
                },
                Some(DeviceGeneration(1)),
            ));
            assert!(matches!(replay.response, WorkerResponse::Error { .. }));
            assert!(engine.deletion.is_none() && engine.secret.is_none());
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(scenario == 0));
        }
        Ok(())
    }

    struct MutationBackend {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        compatible: bool,
    }
    struct MutationSession {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        operation: fido_auth::mutation::PinOperation,
    }
    impl fido_libfido2::NativePinMutationSession for MutationSession {
        fn operation(&self) -> fido_auth::mutation::PinOperation {
            self.operation
        }
        fn pin_retries(&self) -> Option<u8> {
            Some(8)
        }
        fn execute(
            self: Box<Self>,
            secrets: fido_auth::mutation::PinMutationSecrets,
            _: NativeDeadline,
        ) -> fido_auth::mutation::PinMutationResult {
            assert_eq!(secrets.operation(), self.operation);
            drop(secrets);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fido_auth::mutation::PinMutationResult::from_code(self.operation, true, 0, true)
        }
    }
    impl NativeDiscoveryBackend for MutationBackend {
        fn manifest(
            &mut self,
            _: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            Ok(vec![native_device(1)?])
        }
        fn get_info(
            &mut self,
            _: &NativeDeviceKey,
            _: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            Ok(native_info())
        }
        fn prepare_pin_mutation(
            &mut self,
            _: &NativeDeviceKey,
            operation: fido_auth::mutation::PinOperation,
            _: NativeDeadline,
        ) -> Result<Box<dyn fido_libfido2::NativePinMutationSession>, NativeError> {
            Ok(Box::new(MutationSession {
                calls: self.calls.clone(),
                operation: if self.compatible {
                    operation
                } else {
                    fido_auth::mutation::PinOperation::SetPin
                },
            }))
        }
    }
    #[test]
    fn mutation_requires_exact_one_use_preparation_and_secret_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        use fido_auth::mutation::{PinMutationBinding, PinMutationSecrets, PinOperation};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let binding = PinMutationBinding {
            operation: PinOperation::ChangePin,
            session: fido_auth::AcquisitionBinding {
                worker_generation: 1,
                device_generation: DeviceGeneration(1),
                workflow_id: fido_core::WorkflowId::from_raw(1),
                prompt_instance_id: fido_core::PromptInstanceId::from_raw(1),
                acquisition_id: fido_auth::AcquisitionId(1),
            },
            intent_digest: [7; 32],
        };
        for scenario in 0..13 {
            let calls = Arc::new(AtomicUsize::new(0));
            let pin = || {
                fido_auth::PinSecret::collect(|b| {
                    b[..4].copy_from_slice(b"fake");
                    Some(4)
                })
                .map_err(|_| "synthetic PIN")
            };
            let mut bytes = Vec::new();
            fido_auth::mutation::send_mutation_secret(
                &mut bytes,
                binding,
                3,
                PinMutationSecrets::Change {
                    current: pin()?,
                    new: pin()?,
                },
            )
            .map_err(|_| "frame")?;
            if scenario == 9 {
                bytes.pop();
            }
            if scenario == 10 {
                bytes.push(1);
            }
            let mut engine = WorkerEngine::new(
                MutationBackend {
                    calls: calls.clone(),
                    compatible: scenario != 11,
                },
                WorkerGeneration(1),
            )
            .with_secret(Some(Box::new(std::io::Cursor::new(bytes))));
            engine.handle(request(
                WorkerGeneration(1),
                1,
                WorkerRequest::ListDevices,
                None,
            ));
            if scenario != 1 {
                engine.handle(request(
                    WorkerGeneration(1),
                    2,
                    WorkerRequest::PreparePinMutation {
                        device_id: WorkerDeviceId(1),
                        binding,
                    },
                    Some(DeviceGeneration(1)),
                ));
            }
            if scenario == 12 {
                engine.handle(request(
                    WorkerGeneration(1),
                    4,
                    WorkerRequest::HealthCheck,
                    None,
                ));
            }
            let mut submitted = binding;
            let mut worker = WorkerGeneration(1);
            let mut id = 3;
            match scenario {
                2 => submitted.operation = PinOperation::SetPin,
                3 => submitted.session.device_generation = DeviceGeneration(2),
                4 => submitted.session.workflow_id = fido_core::WorkflowId::from_raw(2),
                5 => {
                    submitted.session.prompt_instance_id = fido_core::PromptInstanceId::from_raw(2)
                }
                6 => submitted.session.acquisition_id = fido_auth::AcquisitionId(2),
                7 => worker = WorkerGeneration(2),
                8 => id = 2,
                _ => {}
            }
            let response = engine.handle(request(
                worker,
                id,
                WorkerRequest::ExecutePinMutation { binding: submitted },
                Some(submitted.session.device_generation),
            ));
            if scenario == 0 {
                assert!(matches!(
                    response.response,
                    WorkerResponse::PinMutationCompleted { .. }
                ));
                assert_eq!(
                    response.evidence.mutation_outcome,
                    Some(fido_core::MutationOutcome::ConfirmedSuccessful)
                );
            } else {
                assert!(matches!(response.response, WorkerResponse::Error { .. }));
            }
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(scenario == 0));
            let replay = engine.handle(request(
                WorkerGeneration(1),
                8,
                WorkerRequest::ExecutePinMutation { binding },
                Some(DeviceGeneration(1)),
            ));
            assert!(matches!(replay.response, WorkerResponse::Error { .. }));
            assert!(engine.mutation.is_none() && engine.secret.is_none());
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(scenario == 0));
        }
        Ok(())
    }
}
