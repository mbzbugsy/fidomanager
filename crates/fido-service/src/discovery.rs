//! Read-only authenticator discovery coordination.
//!
//! This module owns renderer-handle minting and translates the process-transparent worker
//! protocol into sanitized domain snapshots. Native device paths and native handles never cross
//! this boundary.

use fido_core::{
    DeviceHandle, DeviceListSnapshot, DeviceOption, DeviceReadStatus, DeviceSnapshot,
    EnumerationEpoch, ExecutionQuiescence, ViewFreshness,
};
use fido_worker_protocol::{
    CancellationId, MAX_DEVICE_STRING_ITEMS, MAX_DEVICE_TEXT_BYTES, MAX_DISCOVERED_DEVICES,
    RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerDeviceId, WorkerDeviceInfo,
    WorkerDiscoveredDevice, WorkerErrorCode, WorkerGeneration, WorkerRequest,
    WorkerRequestEnvelope, WorkerRequestId, WorkerResponse, WorkerResponseEnvelope,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryPolicy {
    pub list_devices_budget_ms: u64,
    pub get_device_info_budget_ms: u64,
}

impl DiscoveryPolicy {
    pub fn validate(self) -> Result<Self, DiscoveryPolicyError> {
        if self.list_devices_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroListDevicesBudget);
        }
        if self.get_device_info_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroGetDeviceInfoBudget);
        }
        Ok(self)
    }
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            list_devices_budget_ms: 2_000,
            get_device_info_budget_ms: 2_000,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPolicyError {
    #[error("list-devices execution budget must be greater than zero")]
    ZeroListDevicesBudget,
    #[error("GetInfo execution budget must be greater than zero")]
    ZeroGetDeviceInfoBudget,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkerEndpointError {
    #[error("worker endpoint is unavailable")]
    Unavailable,
    #[error("worker transport failed")]
    TransportFailure,
    #[error("worker frame exceeded the configured transport bound")]
    FrameTooLarge,
}

/// Service-facing worker endpoint.
///
/// Implementations may use an in-process worker thread today and a child/elevated process later;
/// service semantics must not depend on that placement.
pub trait WorkerEndpoint {
    fn exchange(
        &mut self,
        request: WorkerRequestEnvelope,
    ) -> Result<WorkerResponseEnvelope, WorkerEndpointError>;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error(transparent)]
    Endpoint(#[from] WorkerEndpointError),
    #[error("worker returned error {0:?}")]
    Worker(WorkerErrorCode),
    #[error("worker response did not correlate with the request")]
    ResponseCorrelation,
    #[error("worker returned a response variant that does not match the request")]
    UnexpectedResponse,
    #[error("read-only worker response contained mutation evidence")]
    MutationEvidenceOnReadOnly,
    #[error("worker native execution is not proven quiescent")]
    WorkerNotQuiescent,
    #[error("worker returned too many discovered devices")]
    TooManyDevices,
    #[error("worker returned duplicate device identities in one enumeration")]
    DuplicateDevice,
    #[error("worker returned device data outside the approved output bounds")]
    MalformedDeviceData,
    #[error("authority identifier space is exhausted")]
    IdentifierSpaceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredDeviceTarget {
    pub worker_device_id: WorkerDeviceId,
    pub device_generation: fido_core::DeviceGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisteredDevice {
    handle: DeviceHandle,
    worker_device_id: WorkerDeviceId,
    device_generation: fido_core::DeviceGeneration,
}

#[derive(Debug, Default)]
struct DeviceRegistry {
    devices: Vec<RegisteredDevice>,
    next_handle_raw: u128,
}

impl DeviceRegistry {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            next_handle_raw: 1,
        }
    }

    fn reconcile(
        &mut self,
        discovered: &[WorkerDiscoveredDevice],
    ) -> Result<Vec<(WorkerDiscoveredDevice, DeviceHandle)>, DiscoveryError> {
        let mut next_devices = Vec::with_capacity(discovered.len());
        let mut resolved = Vec::with_capacity(discovered.len());

        for device in discovered {
            let handle = match self.devices.iter().find(|registered| {
                registered.worker_device_id == device.device_id
                    && registered.device_generation == device.device_generation
            }) {
                Some(registered) => registered.handle,
                None => self.mint_handle()?,
            };

            next_devices.push(RegisteredDevice {
                handle,
                worker_device_id: device.device_id,
                device_generation: device.device_generation,
            });
            resolved.push((device.clone(), handle));
        }

        self.devices = next_devices;
        Ok(resolved)
    }

    fn resolve(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.devices
            .iter()
            .find(|registered| registered.handle == handle)
            .map(|registered| RegisteredDeviceTarget {
                worker_device_id: registered.worker_device_id,
                device_generation: registered.device_generation,
            })
    }

    fn clear(&mut self) {
        self.devices.clear();
    }

    fn mint_handle(&mut self) -> Result<DeviceHandle, DiscoveryError> {
        let raw = self.next_handle_raw;
        self.next_handle_raw = self
            .next_handle_raw
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(DeviceHandle::from_raw(raw))
    }
}

pub struct DiscoveryCoordinator<E> {
    endpoint: E,
    worker_generation: WorkerGeneration,
    policy: DiscoveryPolicy,
    registry: DeviceRegistry,
    next_request_id: u64,
    next_cancellation_id: u64,
    next_enumeration_epoch: u64,
}

impl<E: WorkerEndpoint> DiscoveryCoordinator<E> {
    pub fn new(
        endpoint: E,
        worker_generation: WorkerGeneration,
        policy: DiscoveryPolicy,
    ) -> Result<Self, DiscoveryPolicyError> {
        Ok(Self {
            endpoint,
            worker_generation,
            policy: policy.validate()?,
            registry: DeviceRegistry::new(),
            next_request_id: 1,
            next_cancellation_id: 1,
            next_enumeration_epoch: 1,
        })
    }

    pub fn refresh(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        let result = self.refresh_inner();
        if result.is_err() {
            // If enumeration cannot complete coherently, old renderer handles are no longer
            // authoritative evidence of current device presence.
            self.registry.clear();
        }
        result
    }

    pub fn resolve_handle(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.registry.resolve(handle)
    }

    pub fn replace_worker(&mut self, endpoint: E, worker_generation: WorkerGeneration) {
        self.endpoint = endpoint;
        self.worker_generation = worker_generation;
        self.registry.clear();
    }

    fn refresh_inner(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        let list_response = self.exchange_read_only(
            WorkerRequest::ListDevices,
            None,
            self.policy.list_devices_budget_ms,
        )?;

        let discovered = match list_response.response {
            WorkerResponse::DevicesListed { devices } => devices,
            WorkerResponse::Error { code } => return Err(DiscoveryError::Worker(code)),
            _ => return Err(DiscoveryError::UnexpectedResponse),
        };

        validate_discovered_devices(&discovered)?;
        let registered = self.registry.reconcile(&discovered)?;
        let epoch = self.mint_enumeration_epoch()?;
        let mut snapshots = Vec::with_capacity(registered.len());

        for (device, handle) in registered {
            let mut snapshot = base_snapshot(&device, handle);
            let info_response = self.exchange_read_only(
                WorkerRequest::GetDeviceInfo {
                    device_id: device.device_id,
                },
                Some(device.device_generation),
                self.policy.get_device_info_budget_ms,
            )?;

            match info_response.response {
                WorkerResponse::DeviceInfo { info } => {
                    validate_device_info(&info, device.device_id)?;
                    apply_device_info(&mut snapshot, info);
                }
                WorkerResponse::Error { code } => {
                    snapshot.read_status = read_status_for_error(code)?;
                    snapshot.freshness = ViewFreshness::Incomplete;
                }
                _ => return Err(DiscoveryError::UnexpectedResponse),
            }

            snapshots.push(snapshot);
        }

        Ok(DeviceListSnapshot {
            enumeration_epoch: epoch,
            devices: snapshots,
        })
    }

    fn exchange_read_only(
        &mut self,
        request: WorkerRequest,
        device_generation: Option<fido_core::DeviceGeneration>,
        budget_ms: u64,
    ) -> Result<WorkerResponseEnvelope, DiscoveryError> {
        let request_id = WorkerRequestId(self.take_request_id()?);
        let cancellation_id = CancellationId(self.take_cancellation_id()?);
        let envelope = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id,
            cancellation_id,
            operation_class: request.operation_class(),
            worker_generation: self.worker_generation,
            device_generation,
            budget_ms: RequestBudgetMs(budget_ms),
            request,
        };
        envelope
            .validate()
            .map_err(|_| DiscoveryError::UnexpectedResponse)?;

        let response = self.endpoint.exchange(envelope.clone())?;
        validate_response(&envelope, &response)?;
        Ok(response)
    }

    fn take_request_id(&mut self) -> Result<u64, DiscoveryError> {
        let value = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(value)
    }

    fn take_cancellation_id(&mut self) -> Result<u64, DiscoveryError> {
        let value = self.next_cancellation_id;
        self.next_cancellation_id = self
            .next_cancellation_id
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(value)
    }

    fn mint_enumeration_epoch(&mut self) -> Result<EnumerationEpoch, DiscoveryError> {
        let value = self.next_enumeration_epoch;
        self.next_enumeration_epoch = self
            .next_enumeration_epoch
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(EnumerationEpoch(value))
    }
}

fn validate_response(
    request: &WorkerRequestEnvelope,
    response: &WorkerResponseEnvelope,
) -> Result<(), DiscoveryError> {
    if response.protocol_version != WORKER_PROTOCOL_VERSION
        || response.request_id != request.request_id
        || response.worker_generation != request.worker_generation
        || response.device_generation != request.device_generation
    {
        return Err(DiscoveryError::ResponseCorrelation);
    }

    if response.evidence.mutation_outcome.is_some() {
        return Err(DiscoveryError::MutationEvidenceOnReadOnly);
    }
    if response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent {
        return Err(DiscoveryError::WorkerNotQuiescent);
    }

    let response_matches = matches!(
        (&request.request, &response.response),
        (
            WorkerRequest::ListDevices,
            WorkerResponse::DevicesListed { .. }
        ) | (WorkerRequest::ListDevices, WorkerResponse::Error { .. })
            | (
                WorkerRequest::GetDeviceInfo { .. },
                WorkerResponse::DeviceInfo { .. }
            )
            | (
                WorkerRequest::GetDeviceInfo { .. },
                WorkerResponse::Error { .. }
            )
    );

    if !response_matches {
        return Err(DiscoveryError::UnexpectedResponse);
    }

    Ok(())
}

fn validate_discovered_devices(devices: &[WorkerDiscoveredDevice]) -> Result<(), DiscoveryError> {
    if devices.len() > MAX_DISCOVERED_DEVICES {
        return Err(DiscoveryError::TooManyDevices);
    }

    let mut seen = Vec::with_capacity(devices.len());
    for device in devices {
        if seen.contains(&device.device_id) {
            return Err(DiscoveryError::DuplicateDevice);
        }
        seen.push(device.device_id);

        if !optional_text_is_valid(&device.manufacturer) || !optional_text_is_valid(&device.product)
        {
            return Err(DiscoveryError::MalformedDeviceData);
        }
    }

    Ok(())
}

fn validate_device_info(
    info: &WorkerDeviceInfo,
    expected_device_id: WorkerDeviceId,
) -> Result<(), DiscoveryError> {
    if info.device_id != expected_device_id
        || info.versions.len() > MAX_DEVICE_STRING_ITEMS
        || info.extensions.len() > MAX_DEVICE_STRING_ITEMS
        || info.transports.len() > MAX_DEVICE_STRING_ITEMS
        || info.options.len() > MAX_DEVICE_STRING_ITEMS
    {
        return Err(DiscoveryError::MalformedDeviceData);
    }

    let strings_are_valid = info
        .versions
        .iter()
        .chain(info.extensions.iter())
        .chain(info.transports.iter())
        .all(|value| text_is_valid(value));
    let options_are_valid = info
        .options
        .iter()
        .all(|option| text_is_valid(&option.name));

    if !strings_are_valid || !options_are_valid {
        return Err(DiscoveryError::MalformedDeviceData);
    }

    Ok(())
}

fn optional_text_is_valid(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|text| text_is_valid(text))
}

fn text_is_valid(value: &str) -> bool {
    value.len() <= MAX_DEVICE_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn base_snapshot(device: &WorkerDiscoveredDevice, handle: DeviceHandle) -> DeviceSnapshot {
    DeviceSnapshot {
        handle,
        generation: device.device_generation,
        vendor_id: device.vendor_id,
        product_id: device.product_id,
        manufacturer: device.manufacturer.clone(),
        product: device.product.clone(),
        aaguid: None,
        versions: Vec::new(),
        extensions: Vec::new(),
        transports: Vec::new(),
        options: Vec::new(),
        max_message_size: None,
        firmware_version: None,
        read_status: DeviceReadStatus::Ready,
        freshness: ViewFreshness::Incomplete,
    }
}

fn apply_device_info(snapshot: &mut DeviceSnapshot, info: WorkerDeviceInfo) {
    snapshot.aaguid = info.aaguid;
    snapshot.versions = info.versions;
    snapshot.extensions = info.extensions;
    snapshot.transports = info.transports;
    snapshot.options = info
        .options
        .into_iter()
        .map(|option| DeviceOption {
            name: option.name,
            enabled: option.enabled,
        })
        .collect();
    snapshot.max_message_size = info.max_message_size;
    snapshot.firmware_version = info.firmware_version;
    snapshot.read_status = DeviceReadStatus::Ready;
    snapshot.freshness = ViewFreshness::Fresh;
}

fn read_status_for_error(code: WorkerErrorCode) -> Result<DeviceReadStatus, DiscoveryError> {
    match code {
        WorkerErrorCode::DeviceAbsent => Ok(DeviceReadStatus::Unavailable),
        WorkerErrorCode::DeviceBusy => Ok(DeviceReadStatus::Busy),
        WorkerErrorCode::AccessDenied => Ok(DeviceReadStatus::AccessDenied),
        WorkerErrorCode::DeadlineExpired => Ok(DeviceReadStatus::TimedOut),
        WorkerErrorCode::UnsupportedDevice => Ok(DeviceReadStatus::Unsupported),
        WorkerErrorCode::MalformedDeviceData => Ok(DeviceReadStatus::Malformed),
        WorkerErrorCode::Cancelled | WorkerErrorCode::InternalFailure => {
            Ok(DeviceReadStatus::Error)
        }
        WorkerErrorCode::ProtocolMismatch | WorkerErrorCode::WorkerUnavailable => {
            Err(DiscoveryError::Worker(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::{Aaguid, DeviceGeneration, MutationOutcome};
    use fido_worker_protocol::{MAX_DEVICE_TEXT_BYTES, WorkerDeviceOption, WorkerResponseEvidence};

    #[derive(Debug, Clone)]
    struct FakeDevice {
        discovered: WorkerDiscoveredDevice,
        info: Result<WorkerDeviceInfo, WorkerErrorCode>,
    }

    #[derive(Debug)]
    struct FakeEndpoint {
        generation: WorkerGeneration,
        devices: Vec<FakeDevice>,
        force_active_response: bool,
    }

    impl FakeEndpoint {
        fn new(generation: WorkerGeneration, devices: Vec<FakeDevice>) -> Self {
            Self {
                generation,
                devices,
                force_active_response: false,
            }
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
                    execution_quiescence: if self.force_active_response {
                        ExecutionQuiescence::Active
                    } else {
                        ExecutionQuiescence::Quiescent
                    },
                    mutation_outcome: None,
                },
                response,
            }
        }
    }

    impl WorkerEndpoint for FakeEndpoint {
        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            let response = match &request.request {
                WorkerRequest::ListDevices => WorkerResponse::DevicesListed {
                    devices: self
                        .devices
                        .iter()
                        .map(|device| device.discovered.clone())
                        .collect(),
                },
                WorkerRequest::GetDeviceInfo { device_id } => {
                    let Some(device) = self
                        .devices
                        .iter()
                        .find(|device| device.discovered.device_id == *device_id)
                    else {
                        return Ok(self.response(
                            &request,
                            WorkerResponse::Error {
                                code: WorkerErrorCode::DeviceAbsent,
                            },
                        ));
                    };

                    match &device.info {
                        Ok(info) => WorkerResponse::DeviceInfo { info: info.clone() },
                        Err(code) => WorkerResponse::Error { code: *code },
                    }
                }
                _ => WorkerResponse::Error {
                    code: WorkerErrorCode::InternalFailure,
                },
            };

            Ok(self.response(&request, response))
        }
    }

    fn fake_device(generation: u64) -> FakeDevice {
        let device_id = WorkerDeviceId(7);
        FakeDevice {
            discovered: WorkerDiscoveredDevice {
                device_id,
                device_generation: DeviceGeneration(generation),
                vendor_id: 0x1050,
                product_id: 0x0407,
                manufacturer: Some("Example Security".to_owned()),
                product: Some("Roaming Authenticator".to_owned()),
            },
            info: Ok(WorkerDeviceInfo {
                device_id,
                aaguid: Some(Aaguid::from_bytes([0x11; 16])),
                versions: vec!["FIDO_2_1".to_owned()],
                extensions: vec!["credProtect".to_owned()],
                transports: vec!["usb".to_owned()],
                options: vec![WorkerDeviceOption {
                    name: "rk".to_owned(),
                    enabled: true,
                }],
                max_message_size: Some(1_200),
                firmware_version: Some(42),
            }),
        }
    }

    fn coordinator(
        devices: Vec<FakeDevice>,
    ) -> Result<DiscoveryCoordinator<FakeEndpoint>, DiscoveryPolicyError> {
        let worker_generation = WorkerGeneration(3);
        DiscoveryCoordinator::new(
            FakeEndpoint::new(worker_generation, devices),
            worker_generation,
            DiscoveryPolicy::default(),
        )
    }

    #[test]
    fn refresh_publishes_sanitized_snapshot_and_registry_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(9)])?;
        let snapshot = coordinator.refresh()?;

        assert_eq!(snapshot.enumeration_epoch, EnumerationEpoch(1));
        assert_eq!(snapshot.devices.len(), 1);
        let device = &snapshot.devices[0];
        assert_eq!(device.read_status, DeviceReadStatus::Ready);
        assert_eq!(device.freshness, ViewFreshness::Fresh);
        assert_eq!(device.versions, vec!["FIDO_2_1"]);
        assert_eq!(device.transports, vec!["usb"]);
        assert_eq!(
            coordinator.resolve_handle(device.handle),
            Some(RegisteredDeviceTarget {
                worker_device_id: WorkerDeviceId(7),
                device_generation: DeviceGeneration(9),
            })
        );
        Ok(())
    }

    #[test]
    fn removal_invalidates_old_handle_and_replug_gets_fresh_handle()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        let first = coordinator.refresh()?;
        let first_handle = first.devices[0].handle;

        coordinator.endpoint.devices.clear();
        let removed = coordinator.refresh()?;
        assert!(removed.devices.is_empty());
        assert_eq!(coordinator.resolve_handle(first_handle), None);

        coordinator.endpoint.devices.push(fake_device(2));
        let replugged = coordinator.refresh()?;
        let second_handle = replugged.devices[0].handle;
        assert_ne!(first_handle, second_handle);
        assert_eq!(coordinator.resolve_handle(first_handle), None);
        Ok(())
    }

    #[test]
    fn busy_get_info_is_explicitly_incomplete() -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        device.info = Err(WorkerErrorCode::DeviceBusy);
        let mut coordinator = coordinator(vec![device])?;
        let snapshot = coordinator.refresh()?;

        assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Busy);
        assert_eq!(snapshot.devices[0].freshness, ViewFreshness::Incomplete);
        Ok(())
    }

    #[test]
    fn active_native_execution_fails_closed_and_invalidates_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        let initial = coordinator.refresh()?;
        let handle = initial.devices[0].handle;

        coordinator.endpoint.force_active_response = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerNotQuiescent)
        );
        assert_eq!(coordinator.resolve_handle(handle), None);
        Ok(())
    }

    #[test]
    fn malformed_native_text_is_rejected_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        device.discovered.product = Some("x".repeat(MAX_DEVICE_TEXT_BYTES + 1));
        let mut coordinator = coordinator(vec![device])?;

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::MalformedDeviceData)
        );
        Ok(())
    }

    #[test]
    fn read_only_response_rejects_mutation_evidence() -> Result<(), Box<dyn std::error::Error>> {
        struct MutationEvidenceEndpoint;

        impl WorkerEndpoint for MutationEvidenceEndpoint {
            fn exchange(
                &mut self,
                request: WorkerRequestEnvelope,
            ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
                Ok(WorkerResponseEnvelope {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    worker_generation: request.worker_generation,
                    device_generation: request.device_generation,
                    evidence: WorkerResponseEvidence {
                        execution_quiescence: ExecutionQuiescence::Quiescent,
                        mutation_outcome: Some(MutationOutcome::NotDispatched),
                    },
                    response: WorkerResponse::DevicesListed {
                        devices: Vec::new(),
                    },
                })
            }
        }

        let generation = WorkerGeneration(1);
        let mut coordinator = DiscoveryCoordinator::new(
            MutationEvidenceEndpoint,
            generation,
            DiscoveryPolicy::default(),
        )?;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::MutationEvidenceOnReadOnly)
        );
        Ok(())
    }
}
